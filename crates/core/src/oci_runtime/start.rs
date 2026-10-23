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
//! 7. Running（pid 付き）へ状態更新。ハンドルが [`LaunchedProcess::launch_isolation`] を持てば、launch 時の分離の
//!    記録も同じ 1 回の更新で `state.json` へ書く（SUP-6・#2007）。成功したら状態と起動済みプロセスのハンドル（[`StartedContainer`]）を
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
//! 例外として、launcher が [`LaunchMode::SelfBounded`] を宣言した場合（fork する本番 launcher。単一スレッドの
//! 呼び出しを要求する）は、launch を呼び出しスレッドで直接呼ぶ。上限は launcher 自身が `timeout` から導き、
//! start はこの呼び出しを強制しない（`SpawnFailed`・`TimedOut` の枝には到達しない）。予約・claim・解放・Running 記録は
//! 同じ手順で行う（#1816）。
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
//! - `process.user.additionalGids` が空でない（補助グループの適用は未実装。`process.cwd` は pivot 直後に fd 起点で適用し、
//!   `process.user` の uid・gid は launcher が user namespace の写像と照合して適用する。OCI-1・SEC-5）
//! - `process.terminal` が true（端末受け渡し未実装）
//! - `mounts` のうち bind・`/sys` の sysfs（`SysfsMountSpec`。読み取り専用で供給する。#2020）以外の種類・#1910 の拒否規則に反する bind（`BindMountSet`。検証済みの bind は
//!   launcher が pivot 前に適用する。#1915。状態ルートとの重なりは字句・`canonicalize`・mountinfo の実体照合で検査する。`ro` の bind〔#1917〕は未対応）
//! - `linux.namespaces[].path` の指定（既存 namespace への join 未実装）
//! - `network`・`cgroup`・`time` namespace（exec の対応は PID/Mount/UTS/IPC/User のみ）
//! - `linux.namespaces` に user namespace が無い（`process.user` がホストの uid として働いてしまう。
//!   `PermissionDenied`。SEC-5）
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
//! - `linux.uidMappings` / `gidMappings` が非空（`reject_config_id_mappings`。SEC-5・CORE-6・TASK-40。
//!   写像は launcher が権限モデルから導く。受けるかはオーナー判断待ちで #2240 と
//!   `docs/design/config-id-mappings.md` に判断材料があり、決まるまで拒否のまま）
//! - `root.readonly` が true（読み取り専用 rootfs 未実装）
//! - `linux.readonlyPaths` / `maskedPaths` が暗黙の `/dev`・`/dev/pts`・`/dev/shm` と同じか祖先を指す
//!   （`InvalidArgument`。fork・予約より前。SEC-2・CORE-5・#2015。子孫は受ける）
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
//! `process.args[0]` は空でなければ受ける: 絶対パス、名前（pivot 後に `PATH` で探索。#2314）、`/` を含む相対パス（pivot 後に
//! `process.cwd` 起点で解決。`..` は拒否。#2432）。解決は exec 側の担当。コンテナパスはホスト OS 非依存に文字列で判定する
//! （Windows でも `/bin/echo` を受理する。3 OS 一級対応）。
//!
//! # 到達範囲（REPAIR-3）
//!
//! 本関数は launcher の実装を知らない。`process.args` 等がそのまま launcher へ渡り、launcher の返した
//! pid で Running へ遷移するところまでが本関数の責務である。本番の [`ProcessLauncher`]
//! （`ProductionLauncher`。Linux。#1816）は実装済みで、制限ステージ（TASK-37〜39）を通した実プロセスの
//! 起動は `tests/production_launcher.rs`（#1818。実機前提）で通している。supervisor の呼び出しスレッドの
//! 再構成（#1819）は未実装（REPAIR-3）。
//!
//! エラーメッセージは固定文言と静的なフィールドパスのみで、config の値や OS 依存の I/O エラー
//! 文字列を含めない。

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use super::bind_mounts::{BindMountError, BindMountSet, ProtectedFsRoot, audit_bind_mount_error};
use super::cgroup_requirement::CgroupRequirement;
use super::config::{NamespaceKind, OciConfig};
use super::create::{ConfigAudit, validate_bundle_audited};
use super::error::{LifecycleOp, OciRuntimeError};
use super::launch::{
    BundleLock, LaunchMode, LaunchSpec, LaunchedProcess, ProcessLauncher, RootfsDir, StartTimeouts,
};
use super::mountinfo_identity::{
    FsIdentity, MountinfoReadError, dir_identity_chain, fs_identity, mounts_under, parse_mountinfo,
    path_mount_id, read_mountinfo_bounded, source_contains, source_reaches,
};
use super::sysfs_mount::{SysfsMountSpec, audit_sysfs_mount_error};
use super::working_dir::ContainerWorkingDir;
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
///
/// 失敗は [`OciRuntimeError`]（`op` = start・内部エラーと同一の `code`・非ゼロの
/// [`OciRuntimeError::exit_code`]）で返す。標準エラーへの書き出しと終了は呼び出し元の責務
/// （ERR-2・TASK-96.2）。[`recover_interrupted_start`] は ERR-2 の 4 操作外のため `TraitError` のまま。
pub fn start(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    launcher: &Arc<dyn ProcessLauncher>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
) -> Result<StartedContainer, OciRuntimeError> {
    // 変換は最上位 1 か所のみ。内部関数は `TraitError` のまま（波及最小）。
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Start, e);
    let name = OpName::new(START_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || {
        start_inner(store, launcher, req, timeouts).map_err(to_err)
    })
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
pub(super) enum Unbounded {
    /// 上限（＋猶予）を過ぎた、または実行スレッドが結果を返さずに終わった（panic 等）。
    TimedOut,
    /// 実行スレッドを作れなかった（`call` は実行されていない）。
    SpawnFailed,
}

/// `call` を別スレッドで実行し、`limit` ＋ [`LAUNCHER_REPLY_GRACE`] までに戻った結果だけを返す（REPAIR-5）。
///
/// launcher・起動済みプロセスへの呼び出し境界で上限を強制する（`kill.rs` の signaler 呼び出しからも使う）。上限を過ぎたら `Unbounded::TimedOut` を
/// 返して待つのをやめ、後から戻った結果は実行スレッド上で `on_late` に渡す（起動済みプロセスの
/// terminate 等）。結果の受け渡しと「待つのをやめた」印は同じ `Mutex` の下で行うため、戻った結果が
/// 誰にも処理されずに捨てられることはない。実行スレッドが `call` の途中で panic した場合は結果が
/// 無いまま上限を迎え `TimedOut` になる（結果が不明なので予約は残す側に倒す）。実装が永久に戻らない
/// 場合、実行スレッドはプロセス終了まで残る（Rust にスレッドの強制停止は無い）が、呼び出し側は上限で戻る。
pub(super) fn call_bounded<T, F, L>(limit: Duration, call: F, on_late: L) -> Result<T, Unbounded>
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
/// [`ProcessLauncher::confirm_no_process_recorded`] で生存プロセスが無いことを確認する。レコードに記録された
/// cgroup の配置を渡すため、別プロセスで起動した残存も確かめられる（#2011）。確認できない場合
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
    // 所有ロックの取得前に読んだレコードは古い可能性がある（別プロセスの start が pid を記録して
    // ロックを手放した直後に取れた場合）。破壊的な確認（cgroup.kill 等）の前に読み直し、revision と
    // Running・pid なしの予約が変わっていなければ進む。変わっていれば何もせず拒否する（CORE-2・SEC-1）。
    let fresh = store.get(&GetStateRequest::new(id.clone()))?;
    if fresh.revision() != record.revision()
        || fresh.status().state() != ContainerState::Running
        || fresh.status().pid().is_some()
    {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "the start reservation changed while acquiring the owner lock",
        ));
    }
    let record = fresh;
    let confirm = timeouts.confirm();
    let l = Arc::clone(launcher);
    let target = id.clone();
    // 別プロセスで起動した残存は、記録済みの cgroup 配置から確かめる（#2011）。配置は start の手順 5 で 1 回だけ
    // 記録され上書きされない。所有ロック取得後に読み直したレコードの値を使う。
    let recorded = record.cgroup().cloned();
    // confirm_no_process は ID 単位で「残っていれば終了・回収」し得るため、上限超過で本関数が戻った後も
    // 確認が終わるまでプロセス内の予約を保持する（回復の再試行・新しい start が先に進み、その後に
    // 遅れた確認が新しいプロセスを終了させることを防ぐ。CORE-2）。
    let hold = Arc::clone(&reservation);
    match call_bounded(
        confirm,
        move || {
            let result = l.confirm_no_process_recorded(&target, recorded.as_ref(), confirm);
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
    let claimed = claim_inner(store, launcher.as_ref(), req)?;
    launch_inner(store, launcher, claimed, timeouts)
}

/// 起動権を予約済みで、launch だけが残った状態（[`claim_start`] の結果。CORE-2・REPAIR-5・#1819）。
///
/// 状態の読み取り・bundle の検証・所有ロックの取得・予約の更新（`StateStore` と bundle のファイル I/O）を
/// 済ませたもの。呼び出し元（supervisor）はこの段階までを別スレッドで期限つきに実行し、`SelfBounded` の
/// launcher を呼ぶ [`launch_claimed`] だけを単一スレッドの入口スレッドで行える。launch を行わずに捨てる場合は
/// [`ClaimedStart::release`] で予約を Created へ戻す（戻さずに落とすと Running・pid なしの予約が残り、
/// [`recover_interrupted_start`] での回復が要る）。
#[must_use = "a claimed start must be launched or released"]
pub struct ClaimedStart {
    reservation: Arc<StartReservation>,
    id: ContainerId,
    claimed: StateRecord,
    spec: LaunchSpec,
}

impl ClaimedStart {
    /// launch せずに予約を Created へ戻す。戻せなければ `Internal`（予約は残り、回復が要る）。
    pub fn release(self, store: &dyn StateStore) -> Result<(), OciRuntimeError> {
        let Self {
            reservation,
            id,
            claimed,
            spec,
        } = self;
        let result = store.update(&UpdateStateRequest::new(
            ContainerStatus::created(id.clone(), None),
            claimed.revision(),
        ));
        // 予約（プロセス内・所有ロック）は状態を戻した後に手放す。
        drop(spec);
        drop(reservation);
        result.map(|_| ()).map_err(|_| {
            OciRuntimeError::new(
                LifecycleOp::Start,
                ErrorCode::Internal,
                "the start reservation could not be released",
            )
        })
    }
}

impl std::fmt::Debug for ClaimedStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimedStart")
            .field("id", &self.id)
            .finish()
    }
}

/// [`start`] の前半（launch の前まで）。状態を検証し、起動権を予約して [`ClaimedStart`] を返す。
///
/// launcher の launch は呼ばない（bind mount の検証の拒否を `launcher` の監査 sink へ記録するために受け取る）。`StateStore` と bundle のファイル I/O を含むため、呼び出し元が期限を課したい場合は
/// 別スレッドで呼ぶ（REPAIR-5）。失敗時は予約を取っておらず、状態は変わらない（拒否の条件は [`start`] と同じ）。
pub fn claim_start(
    store: &dyn StateStore,
    launcher: &dyn ProcessLauncher,
    req: &StartRequest,
) -> Result<ClaimedStart, OciRuntimeError> {
    claim_inner(store, launcher, req)
        .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e))
}

/// [`start`] の後半。`SelfBounded` の launcher は呼び出しスレッドで直接呼ぶ（単一スレッドの要求）。
///
/// 成功・失敗の件数と所要時間は `recorder` へ操作名 `start` で記録する（launch から状態記録まで）。失敗時の
/// 予約の扱いは [`start`] と同じ。
pub fn launch_claimed(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    launcher: &Arc<dyn ProcessLauncher>,
    claimed: ClaimedStart,
    timeouts: &StartTimeouts,
) -> Result<StartedContainer, OciRuntimeError> {
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Start, e);
    let name = OpName::new(START_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || {
        launch_inner(store, launcher, claimed, timeouts).map_err(to_err)
    })
}

fn claim_inner(
    store: &dyn StateStore,
    launcher: &dyn ProcessLauncher,
    req: &StartRequest,
) -> Result<ClaimedStart, TraitError> {
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

    let spec = build_spec(record.bundle(), req.id(), launcher, store.host_state_root())?;

    // 起動権の所有ロック（プロセス間の排他）を予約の前に取り、launch が終わるまで保持する。所有ロックを
    // 持つプロセスが終了すればカーネルが解放するため、回復はその終了を条件にできる（CORE-2）。
    reservation.lock_owner(record.bundle())?;

    // 起動権の予約。revision 照合つき更新は別プロセスの同時 start と排他になる（CORE-2）。
    let claimed = store.update(&UpdateStateRequest::new(
        ContainerStatus::running(req.id().clone(), None),
        record.revision(),
    ))?;
    Ok(ClaimedStart {
        reservation,
        id: req.id().clone(),
        claimed,
        spec,
    })
}

fn launch_inner(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    prepared: ClaimedStart,
    timeouts: &StartTimeouts,
) -> Result<StartedContainer, TraitError> {
    let ClaimedStart {
        reservation,
        id,
        claimed,
        spec,
    } = prepared;

    let launch_timeout = timeouts.launch();
    let terminate_timeout = timeouts.terminate();
    let l = Arc::clone(launcher);
    // 実行スレッドが launch を終えて後始末を済ませるまで、プロセス内の予約を保持する（CORE-2）。
    let hold = Arc::clone(&reservation);
    let launched = if launcher.launch_mode() == LaunchMode::SelfBounded {
        // 自身で上限を守る launcher（fork する本番 launcher）は単一スレッドの呼び出しを要求するため、
        // 呼び出しスレッドで直接呼ぶ。上限は launcher が `launch_timeout` から導く（REPAIR-5）。
        Ok(l.launch(&spec, launch_timeout))
    } else {
        call_bounded(
            launch_timeout,
            move || l.launch(&spec, launch_timeout),
            move |late: Result<Box<dyn LaunchedProcess>, TraitError>| {
                late_launch_cleanup(late, terminate_timeout);
                drop(hold);
            },
        )
    };
    let process = match launched {
        Ok(Ok(p)) => p,
        // 回収を確認できていない子が残り得る失敗は、予約を Created へ戻さない(戻すと二重起動・delete が通る。CORE-2)。
        Ok(Err(err)) if launcher.last_launch_may_have_left_process() => {
            return Err(TraitError::new(
                err.code(),
                format!(
                    "{}; a launched process may remain, so the start reservation remains until recovered",
                    err.message()
                ),
            ));
        }
        Ok(Err(err)) => return Err(release_claim(store, &id, &claimed, err)),
        // launch は呼ばれていないため予約を戻してよい。
        Err(Unbounded::SpawnFailed) => {
            let err = TraitError::new(ErrorCode::Internal, "failed to run the process launcher");
            return Err(release_claim(store, &id, &claimed, err));
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

    let running = ContainerStatus::running(id.clone(), Some(process.pid()));
    // launch が確定した分離の記録は Running の記録と同じ 1 回の update で書く(exec の根拠。SUP-6・CORE-5・#2007)。
    // 記録を持たない launcher(偽の実装・Linux 以外)では付けず、前の値が引き継がれる(契約 12)。本番 launcher は
    // 記録を作れなければ launch 自体が失敗するため、ここへ記録なしの Running は届かない。
    let mut running_update = UpdateStateRequest::new(running, claimed.revision());
    if let Some(isolation) = process.launch_isolation() {
        running_update = running_update.with_launch_isolation(isolation.clone());
    }
    match store.update(&running_update) {
        // ハンドルは呼び出し元（監視・回収の所有者）へ引き渡す（捨てると回収できない。CORE-1）。
        Ok(record) => Ok(StartedContainer { record, process }),
        Err(err) => {
            // 状態を記録できないまま生きたプロセスを残さない。終了できなかった・上限を超えた場合は
            // 未記録プロセスが残り得ることを呼び出し元へ伝える（元のエラーで隠さない。予約は残す）。
            // 回収を確認できなかったハンドルは未回収レジストリに残り、監視側が引き取って再試行する。
            if terminate_bounded(process, terminate_timeout) {
                Err(release_claim(store, &id, &claimed, err))
            } else {
                Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to record running state and failed to terminate the launched process",
                ))
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
/// （回復可能な失敗状態として保持する。REPAIR-5・CORE-2）。ハンドルは未回収レジストリに残る
/// （[`take_unreaped_processes`]）。
fn late_launch_cleanup(
    late: Result<Box<dyn LaunchedProcess>, TraitError>,
    terminate_timeout: Duration,
) {
    if let Ok(process) = late {
        let _ = terminate_bounded(process, terminate_timeout);
    }
}

/// 回収を確認できなかった起動済みプロセスのハンドル（プロセス内の未回収レジストリ。CORE-1・REPAIR-5）。
///
/// start の後始末（状態記録の失敗後・上限を超えて返った launch）で `terminate` が失敗した、または上限を
/// 超えた後に失敗したハンドルを、捨てずにここへ残す。監視側（supervisor〔TASK-157・SUP 系〕等）が
/// [`take_unreaped_processes`] で引き取り、`terminate` / `wait` を再試行して回収する。start を実行した
/// プロセスが終了すれば子は init（または subreaper）に引き取られて回収されるため、レジストリの寿命は
/// プロセスの寿命で足りる。
static UNREAPED: Mutex<Vec<Box<dyn LaunchedProcess>>> = Mutex::new(Vec::new());

/// 回収を確認できなかったハンドルを未回収レジストリへ残す。
fn keep_unreaped(process: Box<dyn LaunchedProcess>) {
    UNREAPED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(process);
}

/// start の後始末で回収を確認できなかった起動済みプロセスのハンドルをすべて引き取る（CORE-1・REPAIR-5）。
///
/// 返したハンドルの所有権は呼び出し元（監視側）へ移り、レジストリからは消える。呼び出し元は
/// [`LaunchedProcess::terminate`]・[`LaunchedProcess::wait`] を再試行して回収する（ハンドルは `Drop` で
/// 回収しないため、捨てるとゾンビが残り得る）。
pub fn take_unreaped_processes() -> Vec<Box<dyn LaunchedProcess>> {
    std::mem::take(&mut *UNREAPED.lock().unwrap_or_else(PoisonError::into_inner))
}

/// 起動済みプロセスを上限 `timeout` つきで終了・回収する。上限内に回収を確認できたら `true`。
///
/// terminate は `call_bounded` の実行スレッドで呼び、ハンドルは共有の枠を通して渡す。terminate が
/// `Err` を返したら（上限の前後を問わず）ハンドルを未回収レジストリへ残し、実行スレッドを作れなかった
/// 場合も枠に残ったハンドルをレジストリへ残す。上限を超えて戻らない場合はハンドルを実行スレッドが持ち
/// 続け、後から `Err` で戻ればレジストリへ残す（`Ok` なら回収済みとして手放す）。
fn terminate_bounded(process: Box<dyn LaunchedProcess>, timeout: Duration) -> bool {
    let cell = Arc::new(Mutex::new(Some(process)));
    let worker_cell = Arc::clone(&cell);
    let outcome = call_bounded(
        timeout,
        move || {
            let taken = worker_cell
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let Some(process) = taken else {
                return false;
            };
            if process.terminate(timeout).is_ok() {
                true
            } else {
                keep_unreaped(process);
                false
            }
        },
        drop,
    );
    match outcome {
        Ok(reaped) => reaped,
        Err(Unbounded::TimedOut) => false,
        Err(Unbounded::SpawnFailed) => {
            let left = cell.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(process) = left {
                keep_unreaped(process);
            }
            false
        }
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
fn build_spec(
    bundle: &Path,
    id: &ContainerId,
    launcher: &dyn ProcessLauncher,
    state_root: Option<&Path>,
) -> Result<LaunchSpec, TraitError> {
    // destination の拒否は launcher の拒否の記録先へ残す（TOCTOU の再検証。#2594・SEC-4・OCI-4）。手順 5 の
    // `load_resource_limits_audited` で既に拒否された場合はここへ来ないため、1 回の start で高々 1 件。
    let audit = launcher
        .rejection_audit_sink()
        .map(|sink| ConfigAudit { id, sink });
    let (config, rootfs) = validate_bundle_audited(bundle, audit)?;
    let process = config.process().ok_or_else(|| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "config.json: process is required",
        )
    })?;

    // 絶対パス、`/` を含まない名前(pivot 後に `process.env` の `PATH` で解決する。OCI-1・#2314。`PATH` の有無は
    // launcher の fork 前の検証で見る)、`/` を含む相対パス(pivot と cwd の適用後に cwd 起点で解決する。OCI-1・
    // OCI-4・#2432。`..` 等の字句検証は launcher の `Entrypoint::cwd_relative`)のいずれでもよい。ここでは空だけ拒否する。
    let first_is_usable = process.args().first().is_some_and(|a| !a.is_empty());
    if !first_is_usable {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "process.args[0] must not be empty",
        ));
    }
    validate_entrypoint_limits(process.args(), process.env())?;
    let user = process.user();
    let ids = (user.uid(), user.gid());
    // cwd は字句検証だけここで行い、適用は子が pivot 直後に fd 起点で行う（不在・非ディレクトリは launch 側の拒否。OCI-1）。
    let working_dir = ContainerWorkingDir::parse(process.cwd()).ok_or_else(|| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "process.cwd must be a normalized absolute path without .. components",
        )
    })?;
    // uid・gid は launcher が写像と照合して適用する（SEC-5）。補助グループは未実装のため拒否する（REPAIR-3）。
    if !user.additional_gids().is_empty() {
        return Err(unsupported("process.user.additionalGids"));
    }
    if process.terminal() {
        return Err(unsupported("process.terminal"));
    }
    reject_unsupported_linux(&config)?;
    reject_protected_paths_over_implicit_dev(&config)?;
    // user namespace が無いと process.user がホストの uid として働いてしまう（SEC-5）。
    if !config
        .namespaces()
        .iter()
        .any(|n| n.kind() == NamespaceKind::User)
    {
        return Err(TraitError::new(
            ErrorCode::PermissionDenied,
            "a user namespace is required (SEC-5)",
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
    // bind mount の検証は予約と fork の前に終える（失敗してもプロセスのいない Running を残さない。#1915）。
    let bind_mounts = validate_bind_mounts(&config, bundle, &rootfs, state_root, id, launcher)?;
    // `/sys` の sysfs（#2020）。拒否は bind と同じく launcher の監査 sink へ記録する（記録の成否は結果を変えない）。
    let sysfs = SysfsMountSpec::from_mounts(config.mounts()).map_err(|err| {
        let (code, message) = (err.code(), err.message());
        if let Some(sink) = launcher.rejection_audit_sink() {
            let _ = audit_sysfs_mount_error(err, config.mounts(), Some(id), sink);
        }
        TraitError::new(code, message)
    })?;
    // 検査済みの rootfs を、`/` から祖先を含む全要素を symlink 非追従で辿って fd で固定する（SEC-1）。
    // 以後の使用はこの fd に限るため、検査後に祖先や rootfs を差し替えても固定した実体は変わらない。
    // 違反の理由（`RootfsPinError::violation`）は start の経路ではまだ記録しない（拒否の記録先 `rejection_audit_sink` はあるが理由を流していない・未実装。#2623・#1702）。
    let rootfs_dir = RootfsDir::pin(bundle, &rootfs).map_err(TraitError::from)?;
    Ok(LaunchSpec::new(
        rootfs,
        rootfs_dir,
        process.args().to_vec(),
        process.env().to_vec(),
        config.hostname().map(str::to_owned),
        namespaces,
        CgroupRequirement::of_config(&config),
        Arc::new(config),
        id.clone(),
        bind_mounts,
        working_dir,
        ids,
    )
    .with_sysfs(sysfs))
}

/// `mounts[]` を検証済みの bind mount 集合へ変換する（TASK-29 追補・#1915・OCI-4・CORE-5・SEC-1・SEC-4）。
///
/// 種類・オプション・元の字句（[`BindMountSet::from_mounts`]）、元が rootfs・bundle と同一またはその祖先で
/// ないこと、`linux.readonlyPaths` / `maskedPaths` と宛先が重ならないことを検査する。いずれも fork の前に
/// 終わる純粋な字句検査で、実体の照合は適用の段（`exec::mount_binds`）が担う。拒否は launcher の監査 sink
/// （[`ProcessLauncher::rejection_audit_sink`]）へ記録する。記録の成否で拒否は覆さない。
///
/// 状態ルート（`StateStore::host_state_root`）は、元が同一・祖先・子孫のいずれでも拒否する（字句比較と、
/// 元を `canonicalize` した実体の比較。state.json・@revision・@audit.log の改変を防ぐ。SEC-1）。状態ルートを
/// 示せないストアでは、`mounts[]` が非空なら fail-closed で拒否する。
///
/// 検査と適用の間の差し替え（TOCTOU）に備え、検査した状態ルートの実体（`major:minor` と FS 内パス）を
/// 集合へ持たせる。適用の段（`exec::mount_binds`）が、固定した元と配下のマウントに対して毎回照合する（SEC-1）。
fn validate_bind_mounts(
    config: &OciConfig,
    bundle: &Path,
    rootfs: &Path,
    state_root: Option<&Path>,
    id: &ContainerId,
    launcher: &dyn ProcessLauncher,
) -> Result<BindMountSet, TraitError> {
    let reject = |err: BindMountError| -> TraitError {
        let (code, message) = (err.code(), err.message());
        if let Some(sink) = launcher.rejection_audit_sink() {
            // 記録の成否は拒否の結果を変えない。
            let _ = audit_bind_mount_error(err, config.mounts(), Some(id), sink);
        }
        TraitError::new(code, message)
    };
    let set = BindMountSet::from_mounts(config.mounts()).map_err(reject)?;
    if set.is_empty() {
        return Ok(set);
    }
    // 禁止するホストパスは字句正規化できたものだけを使う。できなければ fail-closed（mounts 非空のときのみ）。
    let (Some(rootfs_lex), Some(bundle_lex)) = (lexical_abs(rootfs), lexical_abs(bundle)) else {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the bundle or rootfs path cannot be compared with bind mount sources",
        ));
    };
    set.check_against_host_paths(&[rootfs_lex.as_str(), bundle_lex.as_str()])
        .map_err(reject)?;
    let Some(state_root) = state_root else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "the state store root is unknown, so bind mounts cannot be checked",
        ));
    };
    // 字句比較できない・正規化できない状態ルートは fail-closed。
    let (Some(state_lex), Some(state_real)) = (
        lexical_abs(state_root),
        std::fs::canonicalize(state_root)
            .ok()
            .and_then(|p| lexical_abs(&p)),
    ) else {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the state store root cannot be compared with bind mount sources",
        ));
    };
    set.check_against_protected_trees(&[state_lex.as_str()])
        .map_err(reject)?;
    // symlink 経由で状態ルートへ到達する元を、実体のパスで検出する（存在しない元は適用の段が拒否する）。
    set.check_resolved_sources_against_protected_trees(&[state_real.as_str()], |src| {
        std::fs::canonicalize(src)
            .ok()
            .and_then(|p| lexical_abs(&p))
    })
    .map_err(reject)?;
    // bind mount による別名（`canonicalize` では解決されない）を、mountinfo のファイルシステム内の実体で検出する。
    // `canonicalize` は呼び出しスレッドの mount namespace で解決するため、mountinfo も同じ namespace の
    // `/proc/thread-self/mountinfo` から読む（`/proc/self/mountinfo` はスレッドグループ代表の namespace を示す。SEC-1）。
    let mountinfo = read_mountinfo_bounded("/proc/thread-self/mountinfo").map_err(|e| match e {
        MountinfoReadError::TooLarge => TraitError::new(
            ErrorCode::FailedPrecondition,
            "mountinfo exceeds the size limit, so bind mounts cannot be checked against the state store root",
        ),
        MountinfoReadError::Unreadable => TraitError::new(
            ErrorCode::FailedPrecondition,
            "mountinfo cannot be read, so bind mounts cannot be checked against the state store root",
        ),
    })?;
    let mounts = parse_mountinfo(&mountinfo).ok_or_else(|| {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            "mountinfo is malformed or too large, so bind mounts cannot be checked against the state store root",
        )
    })?;
    // 属するマウントはパスの最長一致ではなく、開いた fd の mnt_id で特定する（overmount で覆われた行に惑わされない）。
    let Some(state_id) =
        path_mount_id(&state_real).and_then(|mnt| fs_identity(&mounts, mnt, &state_real))
    else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "the state store root is not found in mountinfo",
        ));
    };
    // 状態ルート配下の子マウント（別名の bind mount を含む）も保護対象に加える（SEC-1・#1915）。
    let children = mounts_under(&mounts, &state_real);
    let mut roots = build_protected_roots(&state_id, &state_real, &children);
    // 状態ルートの実体（dev, ino）の鎖を fd で固定する。適用の段（restart を含む毎回）が、mountinfo の文字列に依らず
    // 元との同一・祖先・子孫を inode で照合する（SEC-1・SEC-4・#2066）。固定できなければ fail-closed（パスは載せない）。
    let Some(chain) = dir_identity_chain(&state_real) else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "the state store root cannot be pinned, so bind mounts cannot be checked",
        ));
    };
    if let Some(first) = roots.first_mut() {
        *first = first.clone().with_inode_chain(state_real.to_owned(), chain);
    }
    // rootfs・bundle の実体も保護する。rbind が公開する子マウントが別名で rootfs・bundle を含む場合を拒否する（SEC-1）。
    let mut contained = Vec::with_capacity(2);
    for dir in [rootfs, bundle] {
        let identity = std::fs::canonicalize(dir)
            .ok()
            .and_then(|p| lexical_abs(&p))
            .and_then(|real| path_mount_id(&real).and_then(|mnt| fs_identity(&mounts, mnt, &real)));
        let Some(identity) = identity else {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "the bundle or rootfs is not found in mountinfo",
            ));
        };
        roots.push(ProtectedFsRoot::contained(
            identity.dev.clone(),
            identity.path.clone(),
        ));
        contained.push(identity);
    }
    set.check_sources_with(|spec| {
        let Some(real) = std::fs::canonicalize(spec.source())
            .ok()
            .and_then(|p| lexical_abs(&p))
        else {
            // 存在しない元は適用の段が拒否する。
            return false;
        };
        // ディレクトリ・通常ファイル以外・開けない元も適用の段が拒否する（種別・権限の検査）。
        let Some(mnt) = path_mount_id(&real) else {
            return false;
        };
        // 状態ルート自身と配下の子マウントのいずれかに到達する元は拒否する（適用の段と同じ照合を fork 前に行う）。
        // 元のマウントを特定できないときは fail-closed（到達するものとして拒否）。
        source_reaches_protected(&mounts, mnt, &real, spec.recursive(), &state_id, &children)
            || contained.iter().any(|target| {
                source_contains(&mounts, mnt, &real, spec.recursive(), target).unwrap_or(true)
            })
    })
    .map_err(reject)?;
    // 検査済みの実体を集合に持たせる。適用の段（restart を含む毎回）が、固定した元に対して再照合する。
    let set = set.with_protected_roots(roots);
    set.check_against_protected_paths(config.readonly_paths(), config.masked_paths())
        .map_err(reject)?;
    Ok(set)
}

/// 元が状態ルートまたは配下の子マウントのいずれかに到達するか。位置を特定できない場合は到達とみなす（fail-closed）。
fn source_reaches_protected(
    mounts: &[super::mountinfo_identity::MountRow],
    src_mnt_id: u64,
    src_real: &str,
    recursive: bool,
    state_id: &FsIdentity,
    children: &[(FsIdentity, String)],
) -> bool {
    std::iter::once(state_id)
        .chain(children.iter().map(|(id, _)| id))
        .any(|protected| {
            source_reaches(mounts, src_mnt_id, src_real, recursive, protected).unwrap_or(true)
        })
}

/// 保護対象（状態ルートと配下の子マウント）ごとの `ProtectedFsRoot` を作る（SEC-1・#1915）。
///
/// 状態ファイルのハードリンクは、適用の段が毎回走査し直す。走査は保護対象ごとに自分のマウントの木に限り、別の FS の
/// マウントポイントへは降りない（他の FS 上のリンクのせいで無関係な FS 上のディレクトリ元を誤って拒否しない）。
/// 子マウントは自分のマウントポイントを走査根にする。同じマウントポイントに複数のマウントが重なるなど、走査で
/// 実体を確定できないものは「リンクあり」に固定する（fail-closed）。
fn build_protected_roots(
    state_id: &FsIdentity,
    state_real: &str,
    children: &[(FsIdentity, String)],
) -> Vec<ProtectedFsRoot> {
    let prune_for = |dev: &str, scan_root: &str| -> Vec<String> {
        children
            .iter()
            .filter(|(id, point)| {
                id.dev != dev
                    && point != scan_root
                    && Path::new(point).starts_with(Path::new(scan_root))
            })
            .map(|(_, point)| point.clone())
            .collect()
    };
    let mut roots = vec![
        ProtectedFsRoot::new(state_id.dev.clone(), state_id.path.clone(), true)
            .with_scan_root(state_real.to_owned(), prune_for(&state_id.dev, state_real)),
    ];
    for (id, point) in children {
        let shared = children.iter().filter(|(_, p)| p == point).count() > 1;
        let root = ProtectedFsRoot::new(id.dev.clone(), id.path.clone(), true);
        roots.push(if shared {
            root
        } else {
            root.with_scan_root(point.clone(), prune_for(&id.dev, point))
        });
    }
    roots
}

/// 絶対パスを `Component::Normal` だけの `/a/b` 形式へ字句正規化する（`.` は落とす）。
/// 相対・`..` を含む・UTF-8 でない場合は `None`。
fn lexical_abs(path: &Path) -> Option<String> {
    use std::path::Component;
    let mut out = String::new();
    let mut absolute = false;
    for c in path.components() {
        match c {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::Normal(n) => {
                out.push('/');
                out.push_str(n.to_str()?);
            }
            _ => return None,
        }
    }
    (absolute && !out.is_empty()).then_some(out)
}

/// 保護パス（`linux.readonlyPaths` / `maskedPaths`）が暗黙の `/dev` 系マウントと同じか祖先を指す config を、
/// fork・予約より前に `InvalidArgument` で拒否する（SEC-2・CORE-5・OCI-4・TASK-29 追補・#2015）。
///
/// 同じパスか祖先を指すと、覆い・読み取り専用化で最上位のマウントが入れ替わるか覆いの下に隠れ、暗黙のマウントが
/// 期待する fs 種別・識別子（#1609・#2071）が崩れる。本番 launcher では Landlock 段の照合（#2071）が fork 後に
/// `FailedPrecondition` で止めるが、拒否が遅く理由が分かりにくいうえ、exec の再適用（SUP-6）は照合しない。
/// ここで入口に前倒しして閉じる。子孫（`/dev/null` 等）は最上位のマウントを変えないため受ける。
/// 比較は要素単位で、字面だけが似たパス（`/devices`）は祖先ではない。`mounts[]` との衝突
/// （`ImplicitMountConflict`）と揃えて監査には記録しない（config の誤りであり実行時の脱出の試行ではない）。
/// 暗黙マウントの集合は `ImplicitDevMount::ALL`（start は IPC namespace 必須で `/dev/shm` を常に載せる）。
fn reject_protected_paths_over_implicit_dev(config: &OciConfig) -> Result<(), TraitError> {
    let groups = [
        ("linux.readonlyPaths", config.readonly_paths()),
        ("linux.maskedPaths", config.masked_paths()),
    ];
    for (field, paths) in groups {
        for (index, path) in paths.iter().enumerate() {
            let overlaps = crate::dev_mounts::ImplicitDevMount::ALL
                .iter()
                .any(|m| is_same_or_ancestor(path.as_str(), m.destination()));
            if overlaps {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "{field}[{index}] targets a mount point the runtime provides implicitly (/dev, /dev/pts or /dev/shm)"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// 正規化済みの絶対パス `candidate` が `target` と同じか、その祖先かを要素単位で判定する。
fn is_same_or_ancestor(candidate: &str, target: &str) -> bool {
    if candidate == "/" || candidate == target {
        return true;
    }
    target
        .strip_prefix(candidate)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// config の `linux.uidMappings` / `gidMappings` が非空なら `Unimplemented` で拒否する（空配列は受ける）。
///
/// `start` の fork・予約より前に呼ばれる。ID 写像は launcher が権限モデルから導く（`RootlessSingleId` は
/// 呼び出し側の euid / egid の単一写像、`RootlessSubordinateIds` は `/etc/subuid`・`/etc/subgid` の範囲写像）ため、
/// config 指定を受けると SEC-5（コンテナ内 root をホストの非特権 UID へ写す）の契約を迂回しうる。
/// 受けるか拒むかはオーナー判断待ち（#2240。SEC-5・CORE-6・TASK-40。判断材料は
/// `docs/design/config-id-mappings.md`）。未決定のため code は `Unimplemented` のままで、
/// 「拒むと決まった」場合は `InvalidArgument` へ替える案がある（REPAIR-3）。config の誤りであり
/// 脱出の試行ではないため監査には記録しない。
fn reject_config_id_mappings(config: &OciConfig) -> Result<(), TraitError> {
    if !config.uid_mappings().is_empty() || !config.gid_mappings().is_empty() {
        return Err(unsupported("linux.uidMappings / linux.gidMappings"));
    }
    Ok(())
}

fn reject_unsupported_linux(config: &OciConfig) -> Result<(), TraitError> {
    if config.root().readonly() {
        return Err(unsupported("root.readonly"));
    }
    reject_config_id_mappings(config)?;
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
        /// `host_state_root` が返す場所（テストでは実在する一時ディレクトリ）。
        state_root: PathBuf,
        /// 設定すると最初の `get` だけがこの（古い）レコードを返す（ロック取得前の読み取りとの競合の模擬）。
        stale_first_get: Mutex<Option<StateRecord>>,
    }

    impl MemStateStore {
        fn new(fail_update_at: Option<usize>) -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
                fail_update_at,
                update_calls: AtomicUsize::new(0),
                state_root: std::env::temp_dir(),
                stale_first_get: Mutex::new(None),
            }
        }
    }

    impl StateStore for MemStateStore {
        /// bind mount の検証を通すため、実在し bundle の元になり得ない場所を状態ルートとして示す。
        fn host_state_root(&self) -> Option<&Path> {
            Some(self.state_root.as_path())
        }

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
            let mut next = StateRecord::new(
                req.status().clone(),
                cur.bundle().to_path_buf(),
                cur.revision().next()?,
            )?;
            // 契約 12: 指定があれば置き換え、なければ既存の値を引き継ぐ。
            if let Some(l) = req.launch_isolation().or(cur.launch_isolation()) {
                next = next.with_launch_isolation(l.clone());
            }
            records.insert(req.status().id().clone(), next.clone());
            Ok(next)
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            if let Some(stale) = self
                .stale_first_get
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                return Ok(stale);
            }
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
        /// 起動した模擬プロセスの pid（未回収レジストリは並行テストで共有されるため、テストごとに変える）。
        pid: std::sync::atomic::AtomicU32,
        /// `launch_mode` が `SelfBounded` を返すか（#1816）。
        self_bounded: AtomicBool,
        /// launch を呼んだスレッドの ID（呼び出し順）。
        launch_threads: Mutex<Vec<std::thread::ThreadId>>,
        /// 失敗した launch が子を残し得ると答えるか（`last_launch_may_have_left_process`。CORE-2）。
        may_leave: AtomicBool,
        /// `rejection_audit_sink` が返す sink（未設定なら `None`。#1915）。
        audit: std::sync::OnceLock<Arc<crate::audit_log::mount::tests::VecSink>>,
        /// launch が返すハンドルに持たせる分離の記録(未設定なら記録なし。#2007)。
        isolation: Mutex<Option<crate::launch_isolation::LaunchIsolationRecord>>,
        /// `confirm_no_process_recorded` に渡された配置（呼び出し順。#2011）。
        recorded: Mutex<Vec<Option<crate::traits::CgroupPlacement>>>,
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
                pid: std::sync::atomic::AtomicU32::new(4242),
                self_bounded: AtomicBool::new(false),
                launch_threads: Mutex::new(Vec::new()),
                may_leave: AtomicBool::new(false),
                audit: std::sync::OnceLock::new(),
                isolation: Mutex::new(None),
                recorded: Mutex::new(Vec::new()),
            })
        }

        /// 次の launch が返すハンドルに持たせる分離の記録を設定する。
        #[cfg(target_os = "linux")]
        fn set_isolation(&self, record: crate::launch_isolation::LaunchIsolationRecord) {
            *self.isolation.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
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
    struct FakeProcess(
        Arc<AtomicUsize>,
        bool,
        Arc<Gate>,
        NonZeroU32,
        Option<crate::launch_isolation::LaunchIsolationRecord>,
    );

    impl LaunchedProcess for FakeProcess {
        fn pid(&self) -> NonZeroU32 {
            self.3
        }

        fn launch_isolation(&self) -> Option<&crate::launch_isolation::LaunchIsolationRecord> {
            self.4.as_ref()
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
        fn rejection_audit_sink(&self) -> Option<&dyn crate::audit_log::AuditSink> {
            self.audit
                .get()
                .map(|s| s.as_ref() as &dyn crate::audit_log::AuditSink)
        }

        fn launch_mode(&self) -> LaunchMode {
            if self.self_bounded.load(Ordering::SeqCst) {
                LaunchMode::SelfBounded
            } else {
                LaunchMode::CallerBounded
            }
        }

        fn last_launch_may_have_left_process(&self) -> bool {
            self.may_leave.load(Ordering::SeqCst)
        }

        fn confirm_no_process_recorded(
            &self,
            id: &ContainerId,
            recorded: Option<&crate::traits::CgroupPlacement>,
            timeout: Duration,
        ) -> Result<(), TraitError> {
            self.recorded
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(recorded.cloned());
            self.confirm_no_process(id, timeout)
        }

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
            self.launch_threads
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(std::thread::current().id());
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
                NonZeroU32::new(self.pid.load(Ordering::SeqCst)).expect("nonzero"),
                self.isolation
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
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
    ) -> Result<StateRecord, OciRuntimeError> {
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
    fn start_rejected_after_rewrite(name: &str, cfg: &Value) -> OciRuntimeError {
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

    /// `build_spec` を状態ルートを指定して直接呼ぶ（`StateStore` を介さず、ルート不明の経路を検証する）。
    #[cfg(target_os = "linux")]
    fn build_spec_with_state_root(
        name: &str,
        cfg: &Value,
        state_root: Option<&Path>,
    ) -> Result<LaunchSpec, TraitError> {
        let (b, _store) = created(name);
        b.write_config(cfg);
        let launcher = RecordingLauncher::new(false);
        build_spec(
            &b.dir,
            &ContainerId::new(name).expect("id"),
            launcher.as_ref(),
            state_root,
        )
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

    /// REPAIR-5・CORE-1（#1816）: `SelfBounded` の launcher は start を呼んだスレッドで直接呼ばれ、
    /// 起動待ち上限（既定 10 秒）がそのまま渡り、成功は Running（pid つき）で返る。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_self_bounded_launcher_is_called_on_the_caller_thread() {
        let (_b, store) = created("self-bounded-ok");
        let launcher = RecordingLauncher::new(false);
        launcher.self_bounded.store(true, Ordering::SeqCst);
        let record = run(&store, &launcher, "self-bounded-ok").expect("start");
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(record.status().pid(), NonZeroU32::new(4242));
        let threads = launcher.launch_threads.lock().expect("lock").clone();
        assert_eq!(threads, [std::thread::current().id()]);
        assert_eq!(
            launcher.timeouts.lock().expect("lock").as_slice(),
            [Duration::from_secs(10)]
        );
    }

    /// REPAIR-5（#1816）: 既定（`CallerBounded`）は従来どおり別スレッドで呼ばれる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_default_launcher_is_called_on_a_separate_thread() {
        let (_b, store) = created("caller-bounded-thread");
        let launcher = RecordingLauncher::new(false);
        run(&store, &launcher, "caller-bounded-thread").expect("start");
        let threads = launcher.launch_threads.lock().expect("lock").clone();
        assert_eq!(threads.len(), 1);
        assert_ne!(threads.first(), Some(&std::thread::current().id()));
    }

    /// CORE-2（#1816）: `SelfBounded` の launch が `Err` なら、起動権の予約は Created へ戻る。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_self_bounded_launch_failure_releases_the_reservation() {
        let (_b, store) = created("self-bounded-fail");
        let launcher = RecordingLauncher::new(true);
        launcher.self_bounded.store(true, Ordering::SeqCst);
        let err = run(&store, &launcher, "self-bounded-fail").expect_err("launch fails");
        assert_eq!(err.code(), ErrorCode::Internal);
        let got = store
            .get(&GetStateRequest::new(
                ContainerId::new("self-bounded-fail").expect("id"),
            ))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        assert_eq!(launcher.calls(), 1);
    }

    /// CORE-2: 失敗した launch が子を残し得るなら、予約(Running・pid なし)を Created へ戻さず、同じ ID の
    /// 再 start は中断された start として拒否される(二重起動させない)。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_launch_failure_that_may_leave_a_process_keeps_the_reservation() {
        let (_b, store) = created("may-leave");
        let launcher = RecordingLauncher::new(true);
        launcher.self_bounded.store(true, Ordering::SeqCst);
        launcher.may_leave.store(true, Ordering::SeqCst);
        let err = run(&store, &launcher, "may-leave").expect_err("launch fails");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(
            err.message()
                .contains("the start reservation remains until recovered"),
            "{}",
            err.message()
        );
        let got = store
            .get(&GetStateRequest::new(
                ContainerId::new("may-leave").expect("id"),
            ))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Running);
        assert_eq!(got.status().pid(), None);
        let again = run(&store, &launcher, "may-leave").expect_err("second start");
        assert_eq!(again.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
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

    /// CORE-2・REPAIR-5（#1819）: claim_start は launcher を呼ばずに予約し、release で Created へ戻る。
    /// 予約中は同じ ID の start が拒否される。launch_claimed は予約済みから launch して Running へ進む。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_claim_release_and_launch_claimed_split_start() {
        let (_b, store) = created("split");
        let launcher = RecordingLauncher::new(false);
        let claimed = claim_start(&store, launcher.as_ref(), &sid("split")).expect("claim");
        assert_eq!(launcher.calls(), 0);
        let rec = store
            .get(&GetStateRequest::new(
                ContainerId::new("split").expect("id"),
            ))
            .expect("get");
        assert_eq!(rec.status().state(), ContainerState::Running);
        assert!(rec.status().pid().is_none());
        let err = run(&store, &launcher, "split").expect_err("claimed");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        claimed.release(&store).expect("release");
        let rec = store
            .get(&GetStateRequest::new(
                ContainerId::new("split").expect("id"),
            ))
            .expect("get");
        assert_eq!(rec.status().state(), ContainerState::Created);

        let claimed = claim_start(&store, launcher.as_ref(), &sid("split")).expect("claim again");
        let started = launch_claimed(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            claimed,
            &StartTimeouts::default(),
        )
        .expect("launch");
        assert_eq!(launcher.calls(), 1);
        assert_eq!(started.record().status().state(), ContainerState::Running);
        assert!(started.record().status().pid().is_some());
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

    /// SEC-1・OCI-1・OCI-4（#2432）: args[0] が空なら InvalidArgument。`/` を含む相対パスは start の検証を通る
    /// (`..` 等の字句検証は launcher の `Entrypoint::cwd_relative`)。
    #[test]
    fn sec1_start_rejects_empty_entrypoint() {
        let mut cfg = valid_config();
        cfg["process"]["args"] = json!(["", "hi"]);
        let err = start_rejected_after_rewrite("emptyarg", &cfg);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "process.args[0] must not be empty");
    }

    /// SEC-1・SEC-5・CORE-5: start が適用できない指定は黙って無視せず Unimplemented で拒否する。
    #[test]
    fn sec1_start_rejects_unsupported_fields() {
        let cases: Vec<Case> = vec![
            (
                "addgid",
                Box::new(|c| c["process"]["user"]["additionalGids"] = json!([5])),
            ),
            ("tty", Box::new(|c| c["process"]["terminal"] = json!(true))),
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

    /// SEC-5・CORE-6・TASK-40（#2240）: config 指定の ID 写像は uid のみ・gid のみ・両方のどれでも
    /// `Unimplemented` と固定文言で拒否し（launcher 呼び出し 0 回・状態は Created のまま）、空配列は受ける。
    #[test]
    fn sec5_core6_start_rejects_config_id_mappings() {
        let map = json!([{"containerID": 0, "hostID": 1000, "size": 1}]);
        let cases: Vec<(&str, Value, Value)> = vec![
            ("uid", map.clone(), json!([])),
            ("gid", json!([]), map.clone()),
            ("both", map.clone(), map.clone()),
        ];
        for (name, uid, gid) in cases {
            let mut cfg = valid_config();
            cfg["linux"]["uidMappings"] = uid;
            cfg["linux"]["gidMappings"] = gid;
            let err = start_rejected_after_rewrite(&format!("idmap-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::Unimplemented, "case {name}");
            assert_eq!(
                err.message(),
                "start does not support yet: linux.uidMappings / linux.gidMappings",
                "case {name}"
            );
        }
        let mut cfg = valid_config();
        cfg["linux"]["uidMappings"] = json!([]);
        cfg["linux"]["gidMappings"] = json!([]);
        let bytes = serde_json::to_vec(&cfg).expect("json");
        let parsed = super::super::config::parse_config_bytes(&bytes).expect("parse");
        reject_config_id_mappings(&parsed).expect("empty arrays are accepted");
    }

    /// OCI-1・SEC-5: `process.cwd` と非 root の `process.user`（uid・gid）は start で拒否せず、検証済みの値として
    /// launcher へ渡る（適用は子と launcher が行う）。`cwd` の正規化と、`..` を含む `cwd` の拒否も確かめる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci1_start_passes_cwd_and_user_to_launcher() {
        let mut cfg = valid_config();
        cfg["process"]["cwd"] = json!("//work/./dir/");
        cfg["process"]["user"]["uid"] = json!(1000);
        cfg["process"]["user"]["gid"] = json!(1001);
        let spec = build_spec_with_state_root("cwd-user", &cfg, None).expect("spec");
        assert_eq!(
            spec.working_dir(),
            &ContainerWorkingDir::parse(Path::new("/work/dir")).expect("parse")
        );
        assert_eq!(spec.working_dir().components(), ["work", "dir"]);
        assert_eq!(spec.user(), (1000, 1001));

        let mut cfg = valid_config();
        cfg["process"]["cwd"] = json!("/a/../b");
        let err = build_spec_with_state_root("cwd-dotdot", &cfg, None).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "process.cwd must be a normalized absolute path without .. components"
        );
    }

    /// bind mount つきの config（宛先・元・オプションを指定）。
    fn with_mounts(mounts: Value) -> Value {
        let mut cfg = valid_config();
        cfg["mounts"] = mounts;
        cfg
    }

    fn bind_json(dest: &str, source: &str, opts: &[&str]) -> Value {
        json!({"destination": dest, "type": "bind", "source": source, "options": opts})
    }

    /// OCI-4・SEC-1・CORE-5（#1915）: 検証を通らない `mounts[]` は ERR-2 の構造化エラーで拒否し、
    /// launcher は呼ばれず状態は Created のまま。メッセージは固定英文で入力値を含まない。
    #[test]
    fn oci4_sec1_start_rejects_invalid_bind_mounts() {
        let cases: Vec<(&str, Value, ErrorCode, &str)> = vec![
            (
                "proc",
                with_mounts(json!([{"destination": "/mnt", "type": "proc", "source": "proc"}])),
                ErrorCode::Unimplemented,
                "mounts[0]: mount type is not supported (only bind mounts)",
            ),
            (
                "suid",
                with_mounts(json!([bind_json("/mnt", "/srv/x", &["bind", "suid"])])),
                ErrorCode::InvalidArgument,
                "mounts[0]: mount option lifts a mandatory restriction",
            ),
            (
                "shared",
                with_mounts(json!([bind_json("/mnt", "/srv/x", &["bind", "shared"])])),
                ErrorCode::InvalidArgument,
                "mounts[0]: mount propagation options are not supported",
            ),
            (
                "relsrc",
                with_mounts(json!([bind_json("/mnt", "rel/x", &["bind"])])),
                ErrorCode::InvalidArgument,
                "mounts[0]: bind mount source is not a valid absolute path",
            ),
            (
                "nosrc",
                with_mounts(json!([{"destination": "/mnt", "type": "bind", "options": ["bind"]}])),
                ErrorCode::InvalidArgument,
                "mounts[0]: bind mount has no source",
            ),
            (
                "procdst",
                with_mounts(json!([bind_json("/proc/x", "/srv/x", &["bind"])])),
                ErrorCode::InvalidArgument,
                "mounts[0]: bind mount destination is reserved (/proc, /sys or /dev)",
            ),
        ];
        for (name, cfg, code, message) in cases {
            let err = start_rejected_after_rewrite(&format!("rej-bind-{name}"), &cfg);
            assert_eq!(err.code(), code, "case {name}");
            assert_eq!(err.message(), message, "case {name}");
        }
    }

    /// SEC-2・CORE-5・OCI-4（#2015）: 暗黙の `/dev` 系と同じか祖先を指す保護パスは start の fork 前に拒否する
    /// （launcher 0 回・状態は Created のまま）。メッセージは静的で位置だけを含む。
    #[test]
    fn sec2_oci4_start_rejects_protected_paths_over_implicit_dev_mounts() {
        let tail =
            "targets a mount point the runtime provides implicitly (/dev, /dev/pts or /dev/shm)";
        let mk = |ro: Value, masked: Value| {
            let mut c = valid_config();
            c["linux"]["readonlyPaths"] = ro;
            c["linux"]["maskedPaths"] = masked;
            c
        };
        let cases: Vec<(&str, Value, String)> = vec![
            (
                "ro-dev",
                mk(json!(["/dev"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "ro-pts",
                mk(json!(["/dev/pts"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "ro-shm",
                mk(json!(["/dev/shm"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "m-dev",
                mk(json!([]), json!(["/dev"])),
                format!("linux.maskedPaths[0] {tail}"),
            ),
            (
                "m-pts",
                mk(json!([]), json!(["/dev/pts"])),
                format!("linux.maskedPaths[0] {tail}"),
            ),
            (
                "m-shm",
                mk(json!([]), json!(["/dev/shm"])),
                format!("linux.maskedPaths[0] {tail}"),
            ),
            (
                "norm-slash",
                mk(json!(["/dev/"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "norm-dslash",
                mk(json!(["//dev"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "norm-dot",
                mk(json!(["/dev/./pts"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "norm-shm",
                mk(json!(["/dev//shm/"]), json!([])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
            (
                "pos",
                mk(json!(["/data", "/dev/shm"]), json!([])),
                format!("linux.readonlyPaths[1] {tail}"),
            ),
            (
                "order",
                mk(json!(["/dev"]), json!(["/dev/pts"])),
                format!("linux.readonlyPaths[0] {tail}"),
            ),
        ];
        for (name, cfg, message) in cases {
            let err = start_rejected_after_rewrite(&format!("rej-devov-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
            assert_eq!(err.message(), message, "case {name}");
        }
    }

    /// SEC-2（#2015）: 子孫・字面だけ似たパス・無関係なパスは拒否しない。
    #[test]
    fn sec2_protected_paths_under_or_beside_implicit_dev_are_accepted() {
        for p in [
            "/dev/null",
            "/dev/pts/ptmx",
            "/dev/shm/x",
            "/devices",
            "/dev-x",
            "/dev/shmx",
            "/proc/kcore",
        ] {
            let mut cfg = valid_config();
            cfg["linux"]["readonlyPaths"] = json!([p]);
            cfg["linux"]["maskedPaths"] = json!([p]);
            let bytes = serde_json::to_vec(&cfg).expect("json");
            let config = super::super::config::parse_config_bytes(&bytes)
                .unwrap_or_else(|e| panic!("parse {p}: {e:?}"));
            assert!(
                reject_protected_paths_over_implicit_dev(&config).is_ok(),
                "case {p}"
            );
        }
    }

    /// SEC-2（#2015）: 祖先判定は要素単位で、前方一致の取り違えをしない。
    #[test]
    fn sec2_is_same_or_ancestor_is_component_wise() {
        assert!(is_same_or_ancestor("/dev", "/dev"));
        assert!(is_same_or_ancestor("/dev", "/dev/pts"));
        assert!(is_same_or_ancestor("/", "/dev"));
        assert!(!is_same_or_ancestor("/de", "/dev"));
        assert!(!is_same_or_ancestor("/dev/pts", "/dev"));
        assert!(!is_same_or_ancestor("/dev/shmx", "/dev/shm"));
        assert!(!is_same_or_ancestor("/dev/shm/x", "/dev/shm"));
    }

    /// OCI-4・SEC-1（#1915。#2063 の決定 (d)）: ホストパスの字句比較に入る拒否（bundle の祖先・保護パスとの重なり・状態ルート）。
    /// ホストの絶対パスが POSIX 形式であることを前提とするため Linux 限定（Windows はドライブ接頭辞を
    /// 字句正規化できず、macOS は rootfs の固定が未実装）。OS 非依存の判定は `tests/bind_mounts.rs` で照合する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci4_sec1_start_rejects_host_path_overlaps() {
        let tmp = std::env::temp_dir();
        let tmp_src = tmp
            .to_str()
            .expect("utf8 temp dir")
            .trim_end_matches('/')
            .to_owned();
        let forbidden = "mounts[0]: bind mount source is a forbidden host path";
        // 状態ルート（テストでは temp_dir）の子孫を元にしても拒否する（子孫は bundle の祖先判定では通る）。
        let state_child = format!("{tmp_src}/fandhe-state-child");
        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "bundlesrc",
                with_mounts(json!([bind_json("/mnt", &tmp_src, &["bind"])])),
                forbidden,
            ),
            (
                "statechild",
                with_mounts(json!([bind_json("/mnt", &state_child, &["bind", "rw"])])),
                forbidden,
            ),
            (
                "protected",
                {
                    let mut c = with_mounts(json!([bind_json("/etc/secret", "/srv/x", &["bind"])]));
                    c["linux"]["readonlyPaths"] = json!(["/etc/secret"]);
                    c
                },
                "mounts[0]: bind mount destination overlaps a readonly or masked path",
            ),
        ];
        for (name, cfg, message) in cases {
            let err = start_rejected_after_rewrite(&format!("rej-host-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
            assert_eq!(err.message(), message, "case {name}");
        }
    }

    /// SEC-1・OCI-4（#2063 の決定 (d)）: bundle・rootfs の配下の実在する元は受け、状態ルートの配下の実在する元は拒否する。
    /// `MemStateStore` の状態ルートは `temp_dir()` で bundle の祖先になるため使わず、bundle の兄弟の別ディレクトリを
    /// 状態ルートとして `build_spec` を直接呼ぶ。元は実在させ、実体照合（mountinfo）の段を通した結果を照合する。
    /// POSIX 形式のホストパスと rootfs の固定を前提とするため Linux 限定。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_oci4_start_bundle_rootfs_descendants_accepted_state_root_descendant_rejected() {
        let name = "decision-d";
        let (b, _store) = created(name);
        let state = Bundle::new(&format!("{name}-state"));
        let data = b.dir.join("data");
        let sub = b.dir.join("rootfs/sub");
        std::fs::create_dir(&data).expect("data");
        std::fs::create_dir(&sub).expect("sub");
        let data_s = data.to_str().expect("utf8").to_owned();
        let sub_s = sub.to_str().expect("utf8").to_owned();
        b.write_config(&with_mounts(json!([
            bind_json("/data", &data_s, &["bind", "rw"]),
            bind_json("/sub", &sub_s, &["bind"]),
        ])));
        let launcher = RecordingLauncher::new(false);
        let id = ContainerId::new(name).expect("id");
        let spec = build_spec(&b.dir, &id, launcher.as_ref(), Some(state.dir.as_path()))
            .expect("bundle and rootfs descendants are accepted");
        let got: Vec<_> = spec
            .bind_mounts()
            .mounts()
            .iter()
            .map(|m| {
                (
                    m.index(),
                    m.destination().as_str().to_owned(),
                    m.source().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (0, "/data".to_owned(), data_s),
                (1, "/sub".to_owned(), sub_s)
            ]
        );

        // 状態ルートの配下に実在するディレクトリを元にすると拒否する。
        let ctr = state.dir.join("ctr");
        std::fs::create_dir(&ctr).expect("ctr");
        b.write_config(&with_mounts(json!([bind_json(
            "/ctr",
            ctr.to_str().expect("utf8"),
            &["bind"]
        )])));
        let err = build_spec(&b.dir, &id, launcher.as_ref(), Some(state.dir.as_path()))
            .expect_err("state root descendant is rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "mounts[0]: bind mount source is a forbidden host path"
        );
    }

    /// SEC-1・OCI-4（#1915）: 状態ルートを示せないストアでは bind mount つきの start を fail-closed で拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_start_rejects_bind_when_state_root_unknown() {
        let err = build_spec_with_state_root(
            "no-state-root",
            &with_mounts(json!([bind_json("/data", "/srv/data", &["bind"])])),
            None,
        )
        .expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "the state store root is unknown, so bind mounts cannot be checked"
        );
    }

    fn sysfs_json(dest: &str, opts: &[&str]) -> Value {
        json!({"destination": dest, "type": "sysfs", "source": "sysfs", "options": opts})
    }

    /// SEC-2・OCI-4（#2020）: 受けない sysfs の指定は ERR-2 の構造化エラーで拒否し、launcher は呼ばれない。
    #[test]
    fn sec2_oci4_start_rejects_invalid_sysfs() {
        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "dest",
                with_mounts(json!([sysfs_json("/x", &["ro"])])),
                "mounts[0]: sysfs mount destination must be /sys",
            ),
            (
                "rw",
                with_mounts(json!([sysfs_json("/sys", &["rw"])])),
                "mounts[0]: sysfs mount option lifts a mandatory restriction",
            ),
            (
                "unknown",
                with_mounts(json!([sysfs_json("/sys", &["defaults"])])),
                "mounts[0]: unsupported sysfs mount option",
            ),
        ];
        for (name, cfg, message) in cases {
            let err = start_rejected_after_rewrite(&format!("rej-sysfs-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
            assert_eq!(err.message(), message, "case {name}");
        }
    }

    /// SEC-2・OCI-4（#2020）: 正しい sysfs は launcher へ `spec.sysfs_mount()` として渡り、bind は空のまま。
    /// 成功する start は rootfs の固定（Linux 限定）を要するため Linux 限定。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec2_oci4_start_passes_sysfs_to_launcher() {
        let name = "sysfs-ok";
        let b = Bundle::new(name);
        b.write_config(&with_mounts(json!([sysfs_json(
            "/sys",
            &["nosuid", "noexec", "nodev", "ro"]
        )])));
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(None);
        create(&store, &OpRecorder::new(), &b.create_req(name)).expect("create");
        let launcher = RecordingLauncher::new(false);
        let record = run(&store, &launcher, name).expect("start");
        assert_eq!(record.status().state(), ContainerState::Running);
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        assert_eq!(spec.sysfs_mount().map(|s| s.index()), Some(0));
        assert!(spec.bind_mounts().is_empty());
    }

    /// OCI-4・OCI-5（#1915）: 検証を通った bind は launcher へ `spec.bind_mounts()` として渡り、
    /// Landlock の入力である `spec.config().mounts()` と同じ並び・宛先になる。
    /// 成功する start は rootfs の固定（Linux 限定）を要するため Linux 限定。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci4_start_passes_validated_bind_mounts_to_launcher() {
        let name = "bind-ok";
        let b = Bundle::new(name);
        b.write_config(&with_mounts(json!([
            bind_json("/data", "/srv/data", &["bind", "rw"]),
            bind_json("/cache", "/srv/cache", &["rbind", "noexec"]),
        ])));
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(None);
        create(&store, &OpRecorder::new(), &b.create_req(name)).expect("create");
        let launcher = RecordingLauncher::new(false);
        let record = run(&store, &launcher, name).expect("start");
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(launcher.calls(), 1);
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        let got: Vec<_> = spec
            .bind_mounts()
            .mounts()
            .iter()
            .map(|m| {
                (
                    m.index(),
                    m.destination().as_str().to_owned(),
                    m.source().to_owned(),
                    m.read_only(),
                    m.noexec(),
                    m.recursive(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    0,
                    "/data".to_owned(),
                    "/srv/data".to_owned(),
                    false,
                    false,
                    false
                ),
                (
                    1,
                    "/cache".to_owned(),
                    "/srv/cache".to_owned(),
                    false,
                    true,
                    true
                ),
            ]
        );
        let config_dests: Vec<_> = spec
            .config()
            .mounts()
            .iter()
            .map(|m| m.mount_destination().as_str().to_owned())
            .collect();
        assert_eq!(config_dests, ["/data", "/cache"]);
    }

    /// SEC-1（#2066）: start の段が状態ルートの inode の鎖（先頭が状態ルート自身）を固定して launcher へ渡す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_start_pins_state_root_inode_chain() {
        use std::os::unix::fs::MetadataExt as _;
        let name = "bind-pin";
        let b = Bundle::new(name);
        b.write_config(&with_mounts(json!([bind_json(
            "/data",
            "/srv/data",
            &["bind", "rw"]
        )])));
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(None);
        create(&store, &OpRecorder::new(), &b.create_req(name)).expect("create");
        let launcher = RecordingLauncher::new(false);
        run(&store, &launcher, name).expect("start");
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        let meta = std::fs::metadata(std::env::temp_dir()).expect("state root");
        let first_state = spec
            .bind_mounts()
            .protected_roots()
            .iter()
            .find(|r| !r.is_containment_only())
            .expect("state root");
        assert_eq!(
            first_state.inode_chain().first(),
            Some(&(meta.dev(), meta.ino()))
        );
        assert!(first_state.inode_chain().len() >= 2);
        // 適用の段が辿り直すホスト側パス（#2129）。
        let real = std::fs::canonicalize(std::env::temp_dir()).expect("canonical");
        assert_eq!(first_state.chain_path(), real.to_str());
    }

    /// SEC-4（#1915）: 設定の検証での拒否は launcher の sink へ宛先のみで 1 件記録される。sink が無くても
    /// エラーは同じ。
    #[test]
    fn sec4_start_records_bind_rejection_to_launcher_audit_sink() {
        let cfg = with_mounts(json!([bind_json(
            "/mnt/x",
            "/secret-host-dir",
            &["bind", "suid"]
        )]));
        let (b, store) = created("rej-bind-audit");
        b.write_config(&cfg);
        let launcher = RecordingLauncher::new(false);
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(false));
        assert!(launcher.audit.set(Arc::clone(&sink)).is_ok());
        let err = run(&store, &launcher, "rej-bind-audit").expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(launcher.calls(), 0);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        let line = format!("{:?}", recs[0]);
        assert!(line.contains("/mnt/x"), "{line}");
        assert!(!line.contains("secret-host-dir"), "{line}");
        // sink 無し(既定)でも拒否の内容は同じ。
        let err2 = start_rejected_after_rewrite("rej-bind-nosink", &cfg);
        assert_eq!(err2.code(), err.code());
        assert_eq!(err2.message(), err.message());
    }

    /// SEC-4・OCI-4（#2594）: create 後に書き換えられた `mounts[].destination`（遡り・`/`・相対 `..`）の拒否は、
    /// launcher の拒否の記録先へ mount 層・`path` なしで 1 件記録される。sink が無くても code・message は同じ。
    #[test]
    fn sec4_start_records_destination_rejection_to_launcher_audit_sink() {
        for (i, dest) in ["/../..", "/", "run/../../.."].into_iter().enumerate() {
            let cfg = with_mounts(json!([bind_json(dest, "/srv/x", &["bind", "rw"])]));
            let name = format!("rej-dest-audit-{i}");
            let (b, store) = created(&name);
            b.write_config(&cfg);
            let launcher = RecordingLauncher::new(false);
            let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(false));
            assert!(launcher.audit.set(Arc::clone(&sink)).is_ok());
            let err = run(&store, &launcher, &name).expect_err("must fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{dest}");
            assert_eq!(launcher.calls(), 0);
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{dest}");
            assert_eq!(
                recs[0].container_id().map(|c| c.as_str()),
                Some(name.as_str())
            );
            assert!(
                matches!(
                    recs[0].event(),
                    crate::audit_log::AuditEvent::Mount {
                        path: None,
                        reason: None,
                        ..
                    }
                ),
                "{:?}",
                recs[0]
            );
            let err2 = start_rejected_after_rewrite(&format!("rej-dest-nosink-{i}"), &cfg);
            assert_eq!(err2.code(), err.code());
            assert_eq!(err2.message(), err.message());
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

    /// 試験用の分離の記録(`/` が `(dev, ino)`・Landlock は rootfs のルール 1 件)。
    #[cfg(target_os = "linux")]
    fn iso_record(dev: u64, ino: u64) -> crate::launch_isolation::LaunchIsolationRecord {
        use crate::launch_isolation::{
            LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        let landlock =
            RecordedLandlock::new(0x3f, vec![RecordedRule::new(RecordedTarget::Root, 0x0f)])
                .expect("landlock");
        LaunchIsolationRecord::from_parts(RootIdentity::new(dev, ino), landlock)
    }

    /// SUP-6(#2007): ハンドルが持つ分離の記録は、Running の更新と同じ update で状態へ載る。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup6_running_record_carries_launch_isolation() {
        let (_b, store) = created("iso-carry");
        let launcher = RecordingLauncher::new(false);
        launcher.set_isolation(iso_record(7, 11));
        let record = run(&store, &launcher, "iso-carry").expect("start");
        let got = record.launch_isolation().expect("recorded");
        assert_eq!(got.root().dev(), 7);
        assert_eq!(got.root().ino(), 11);
        assert!(got == &iso_record(7, 11));
        let stored = store
            .get(&GetStateRequest::new(
                ContainerId::new("iso-carry").expect("id"),
            ))
            .expect("get");
        assert!(stored.launch_isolation() == Some(&iso_record(7, 11)));
    }

    /// SUP-6(#2007): 記録を持たないハンドルでは、従来どおり分離の記録は付かない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup6_running_record_without_launch_isolation_is_unchanged() {
        let (_b, store) = created("iso-none");
        let launcher = RecordingLauncher::new(false);
        let record = run(&store, &launcher, "iso-none").expect("start");
        assert!(record.launch_isolation().is_none());
    }

    /// SEC-1・SUP-6(#2007): Running の更新に失敗したら Created へ戻り、分離の記録も残らない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_failed_running_write_leaves_no_launch_isolation() {
        let b = Bundle::new("iso-upd-fail");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("iso-upd-fail")).expect("create");
        let launcher = RecordingLauncher::new(false);
        launcher.set_isolation(iso_record(7, 11));
        let err = run(&store, &launcher, "iso-upd-fail").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.terminations(), 1);
        let stored = store
            .get(&GetStateRequest::new(
                ContainerId::new("iso-upd-fail").expect("id"),
            ))
            .expect("get");
        assert!(stored.launch_isolation().is_none());
    }

    /// SEC-5: user namespace が無い config（ホスト root での起動になる）は PermissionDenied で拒否する。
    #[test]
    fn sec5_start_rejects_missing_user_namespace() {
        let mut cfg = valid_config();
        cfg["linux"]["namespaces"] = json!([{"type": "pid"}, {"type": "mount"}]);
        let err = start_rejected_after_rewrite("no-userns", &cfg);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "a user namespace is required (SEC-5)");
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

    /// 未回収レジストリから `pid` のハンドルだけを引き取る。レジストリは並行テストで共有されるため、
    /// 取り出しと残りの書き戻しを 1 回のロックの中で行い、他のテストから一時的に空に見えないようにする。
    #[cfg(target_os = "linux")]
    fn take_unreaped_pid(pid: u32) -> Vec<Box<dyn LaunchedProcess>> {
        let mut registry = UNREAPED.lock().unwrap_or_else(PoisonError::into_inner);
        let (mine, others): (Vec<_>, Vec<_>) = std::mem::take(&mut *registry)
            .into_iter()
            .partition(|p| p.pid().get() == pid);
        *registry = others;
        mine
    }

    /// REPAIR-5・CORE-1: 状態更新と terminate の両方に失敗したら、終了失敗を Internal で伝え、回収を
    /// 確認できなかったハンドルは捨てずに未回収レジストリへ残す（監視側が引き取って再試行できる）。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_start_reports_terminate_failure() {
        let b = Bundle::new("term-fail");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("term-fail")).expect("create");
        let launcher = RecordingLauncher::new(false);
        launcher.pid.store(5101, Ordering::SeqCst);
        launcher.fail_terminate.store(true, Ordering::SeqCst);
        let err = run(&store, &launcher, "term-fail").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(launcher.terminations(), 1);
        let kept = take_unreaped_pid(5101);
        assert_eq!(kept.len(), 1);
        // 引き取った監視側は同じハンドルで再試行できる（模擬プロセスは terminate 済みとして終了扱い）。
        let handle = kept.into_iter().next().expect("handle");
        assert_eq!(
            handle.wait(Duration::ZERO).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
        assert_eq!(take_unreaped_pid(5101).len(), 0);
    }

    /// REPAIR-5・CORE-1: 上限を超えて返った launch の後始末で terminate が失敗しても、ハンドルは未回収
    /// レジストリへ残る。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_late_launch_keeps_unreaped_handle() {
        let (_b, store) = created("late-unreaped");
        let launcher = RecordingLauncher::new(false);
        launcher.pid.store(5102, Ordering::SeqCst);
        launcher.fail_terminate.store(true, Ordering::SeqCst);
        launcher.gate.set_open(false);
        let err = start(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            &sid("late-unreaped"),
            &short_timeouts(),
        )
        .expect_err("must time out");
        assert_eq!(err.code(), ErrorCode::Timeout);
        launcher.gate.set_open(true);
        let kept = Mutex::new(Vec::new());
        assert!(eventually(Duration::from_secs(10), || {
            let mut got = kept.lock().expect("lock");
            got.extend(take_unreaped_pid(5102));
            got.len() == 1
        }));
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
    ///
    /// 解放は呼び出し側が `unlock()` で明示する。`flock` は open file description に付くため、並行する
    /// テストの `Command::spawn` が fork から exec までの間この記述子を引き継ぐと、`drop`（close）だけでは
    /// ロックが外れない（#1537）。
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
        other.unlock().expect("unlock other owner");
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
        other.unlock().expect("unlock other owner");
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
        // CORE-3: cgroup 指定の無い config では要件なし。
        assert!(!spec.cgroup_requirement().is_required());
    }

    /// #2019・CORE-3: 資源つきの config を start すると、launcher へ渡る `LaunchSpec` は cgroup 要件ありで、
    /// config の `linux.resources` が具体値で載る。create 後に `cgroupsPath` を足されたら起動前に拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn core3_start_carries_resources_and_requires_cgroup() {
        use crate::oci_runtime::ByteLimit;
        let b = Bundle::new("resources");
        let mut cfg = valid_config();
        cfg["linux"]["resources"] = json!({"memory": {"limit": 67108864}, "pids": {"limit": 64}});
        b.write_config(&cfg);
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(None);
        create(&store, &OpRecorder::new(), &b.create_req("resources")).expect("create");
        let launcher = RecordingLauncher::new(false);
        run(&store, &launcher, "resources").expect("start");
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        assert!(spec.cgroup_requirement().is_required());
        assert_eq!(spec.cgroup_requirement().reasons(), vec!["linux.resources"]);
        let limits = spec.config().linux_resources().expect("resources");
        assert_eq!(limits.memory_max(), Some(ByteLimit::Bytes(67_108_864)));
        assert_eq!(limits.pids_limit(), Some(64));

        let mut rewritten = valid_config();
        rewritten["linux"]["cgroupsPath"] = json!("/x");
        let err = start_rejected_after_rewrite("resources-path", &rewritten);
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        // 委譲スコープの外へ出る指定（`..`）も値を見ずに起動前に拒否する（#2010・SEC-1）。
        rewritten["linux"]["cgroupsPath"] = json!("../escape");
        let err = start_rejected_after_rewrite("resources-path-dotdot", &rewritten);
        assert_eq!(err.code(), ErrorCode::Unimplemented);
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
        probe.unlock().expect("unlock probe");
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

    /// 予約（Running・pid なし）のレコードを、cgroup の配置つき（`None` なら配置なし）で直接ストアへ置く。
    #[cfg(target_os = "linux")]
    fn claimed_with_cgroup(
        name: &str,
        placement: Option<crate::traits::CgroupPlacement>,
    ) -> (Bundle, MemStateStore, ContainerId) {
        let (b, store) = created(name);
        let id = ContainerId::new(name).expect("id");
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        let mut next = StateRecord::new(
            ContainerStatus::running(id.clone(), None),
            rec.bundle().to_path_buf(),
            rec.revision().next().expect("next"),
        )
        .expect("record");
        if let Some(p) = placement {
            next = next.with_cgroup(p);
        }
        store
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), next);
        (b, store, id)
    }

    /// CORE-2・SEC-1（#2011）: 回復は、レコードに記録された cgroup の配置をそのまま launcher へ渡す。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_issue2011_recover_passes_recorded_placement_to_launcher() {
        let placement = crate::traits::CgroupPlacement::new(
            crate::traits::CgroupScope::new("/user.slice/x.scope").expect("scope"),
            crate::traits::StateRevision::from_raw(3),
        );
        let (_b, store, id) = claimed_with_cgroup("rec-placement", Some(placement.clone()));
        let launcher = RecordingLauncher::new(false);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        let got = recover(&store, &launcher, &id).expect("recover");
        assert_eq!(got.status().state(), ContainerState::Created);
        assert_eq!(
            launcher.recorded.lock().unwrap().clone(),
            vec![Some(placement)]
        );
    }

    /// CORE-2・SEC-1: ロック取得前に読んだ予約が古い（別プロセスの start が間に pid を記録した）場合、
    /// 回復は破壊的な確認へ進まず拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_recover_aborts_when_pid_recorded_between_read_and_lock() {
        let (_b, store, id) = claimed_with_cgroup("rec-race", None);
        let stale = store.get(&GetStateRequest::new(id.clone())).expect("get");
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), std::num::NonZeroU32::new(4242)),
                stale.revision(),
            ))
            .expect("record pid");
        *store.stale_first_get.lock().unwrap() = Some(stale);
        let launcher = RecordingLauncher::new(false);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        let err = recover(&store, &launcher, &id).expect_err("must abort");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(launcher.recorded.lock().unwrap().is_empty());
        let got = store.get(&GetStateRequest::new(id)).expect("get");
        assert_eq!(got.status().pid(), std::num::NonZeroU32::new(4242));
    }

    /// CORE-2（#2011）: 配置の記録が無いレコードでは `None` を渡す（launcher が fail-closed にする）。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_issue2011_recover_passes_none_without_recorded_placement() {
        let (_b, store, id) = claimed_with_cgroup("rec-none", None);
        let launcher = RecordingLauncher::new(false);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        recover(&store, &launcher, &id).expect("recover");
        assert_eq!(launcher.recorded.lock().unwrap().clone(), vec![None]);
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

    /// ERR-2・TASK-96.2: 未 create の start が op = start・NOT_FOUND・終了コード 3・構造化 1 行で得られ、失敗が計数される。
    #[test]
    fn err2_start_unknown_container_is_not_found() {
        let store = MemStateStore::new(None);
        let launcher = RecordingLauncher::new(false);
        let rec = OpRecorder::new();
        let err = start(
            &store,
            &rec,
            &dynl(&launcher),
            &sid("ghost"),
            &StartTimeouts::default(),
        )
        .expect_err("must fail");
        assert_eq!(err.op(), LifecycleOp::Start);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.exit_code().get(), 3);
        let mut out = Vec::new();
        err.write_json_line(&mut out).expect("write");
        let line = String::from_utf8(out).expect("utf8");
        assert!(
            line.starts_with("{\"op\":\"start\",\"code\":\"NOT_FOUND\",\"message\":"),
            "{line}"
        );
        assert!(line.ends_with("}\n"));
        let stats = rec
            .snapshot_op(&OpName::new("start").expect("name"))
            .expect("recorded");
        assert_eq!(stats.failure(), 1);
    }

    /// ERR-2・TASK-96.2: Created 以外の start が FAILED_PRECONDITION・終了コード 5 になる。
    #[test]
    fn err2_start_non_created_is_failed_precondition() {
        let (_b, store) = created("err2-twice");
        let id = ContainerId::new("err2-twice").expect("id");
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        // 1 回目の start は Linux 以外では rootfs 固定が未実装（Unimplemented）で成功しないため、
        // 状態検査（rootfs 固定より前）だけを 3 OS で検証できるよう Running を直接設定する。
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id, std::num::NonZeroU32::new(4242)),
                rec.revision(),
            ))
            .expect("mark running");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "err2-twice").expect_err("second start");
        assert_eq!(err.op(), LifecycleOp::Start);
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.exit_code().get(), 5);
    }

    /// SEC-1（#1915）: 他の FS 上のハードリンクは、無関係な FS の保護対象のリンク判定に混ぜない。
    /// 状態ルート直下の別 FS のマウントポイント配下にだけリンクがあるとき、状態ルート側は「なし」、子マウント側は「あり」。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_hard_link_scan_is_confined_to_each_protected_filesystem() {
        let base = std::env::temp_dir().join(format!("fandhe-oci-hl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let state = base.join("state");
        let sub = state.join("sub");
        std::fs::create_dir_all(&sub).expect("mkdir");
        std::fs::write(state.join("plain"), b"x").expect("write");
        std::fs::write(sub.join("f"), b"x").expect("write");
        std::fs::hard_link(sub.join("f"), sub.join("g")).expect("link");
        let state_s = state.to_str().expect("utf8").to_owned();
        let sub_s = sub.to_str().expect("utf8").to_owned();
        let state_id = FsIdentity {
            dev: "8:1".to_owned(),
            path: "/srv/state".to_owned(),
        };
        let children = vec![(
            FsIdentity {
                dev: "8:2".to_owned(),
                path: "/c1".to_owned(),
            },
            sub_s.clone(),
        )];
        let roots = build_protected_roots(&state_id, &state_s, &children);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].dev(), "8:1");
        assert!(
            !roots[0].has_hard_linked_files(),
            "other FS link must not count"
        );
        assert_eq!(roots[1].dev(), "8:2");
        assert!(roots[1].has_hard_linked_files());
        // 同じ FS（同じ dev）の子マウントは枝刈りしない（リンクは状態ルート側でも見つかる）。
        let same = vec![(
            FsIdentity {
                dev: "8:1".to_owned(),
                path: "/srv/state/sub".to_owned(),
            },
            sub_s,
        )];
        let roots = build_protected_roots(&state_id, &state_s, &same);
        assert!(roots[0].has_hard_linked_files());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// SEC-1（#1915）: 同じマウントポイントに複数のマウントが重なる子は走査で確定できないため「リンクあり」に固定する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_shared_mount_point_child_is_fixed_to_linked() {
        let base = std::env::temp_dir().join(format!("fandhe-oci-hl2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let sub = base.join("sub");
        std::fs::create_dir_all(&sub).expect("mkdir");
        let state_s = base.to_str().expect("utf8").to_owned();
        let sub_s = sub.to_str().expect("utf8").to_owned();
        let state_id = FsIdentity {
            dev: "8:1".to_owned(),
            path: "/s".to_owned(),
        };
        let child = |dev: &str| {
            (
                FsIdentity {
                    dev: dev.to_owned(),
                    path: "/".to_owned(),
                },
                sub_s.clone(),
            )
        };
        let roots = build_protected_roots(&state_id, &state_s, &[child("8:2"), child("8:3")]);
        assert!(roots[1].has_hard_linked_files());
        assert!(roots[2].has_hard_linked_files());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// SEC-1（#1915）: rbind が公開する子マウントが別名で bundle を含むとき、元の位置を問わず拒否する。
    /// bundle の配下だけを指す子マウントや無関係な FS の元は拒否しない。
    #[test]
    fn sec1_rbind_child_mount_containing_bundle_is_rejected() {
        use super::super::mountinfo_identity::parse_mountinfo;
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 /srv/bundle /bundle rw - ext4 /dev/sda1 rw\n\
                    30 10 8:1 / /opt/export rw - ext4 /dev/sda1 rw\n\
                    40 30 8:1 /srv/bundle /opt/export/inner rw - ext4 /dev/sda1 rw\n\
                    50 10 8:1 /srv/bundle/data /opt/data rw - ext4 /dev/sda1 rw\n\
                    60 10 8:5 / /opt/other rw - ext4 /dev/sda5 rw\n\
                    70 60 8:1 /srv/bundle /opt/other/inner rw - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let bundle = fs_identity(&mounts, 20, "/bundle").expect("bundle");
        // /opt/export 自体は FS の `/` なので祖先として含む（字句検査でも拒否される形）。
        assert_eq!(
            source_contains(&mounts, 30, "/opt/export", true, &bundle),
            Some(true)
        );
        // 子マウント経由の別名: root が `/srv/bundle` の子を持つ別 FS の元を rbind。
        assert_eq!(
            source_contains(&mounts, 60, "/opt/other", true, &bundle),
            Some(true)
        );
        // 非再帰（bind）なら子マウントは公開されず、元自身（8:5）は含まない。
        assert_eq!(
            source_contains(&mounts, 60, "/opt/other", false, &bundle),
            Some(false)
        );
        // bundle の配下だけを指す元は含まない。
        assert_eq!(
            source_contains(&mounts, 50, "/opt/data", true, &bundle),
            Some(false)
        );
        // 位置を特定できない元は None（呼び出し側が fail-closed）。
        assert_eq!(source_contains(&mounts, 99, "/x", true, &bundle), None);
    }

    /// SEC-1（#1915）: 状態ルート配下の子マウントの別名を元にした bind は、start の検査（fork 前）で拒否される。
    #[test]
    fn sec1_start_check_rejects_alias_of_nested_state_mount() {
        use super::super::mountinfo_identity::parse_mountinfo;
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 /srv/state /state rw - ext4 /dev/sda1 rw\n\
                    30 20 8:2 /c1 /state/c1 rw - ext4 /dev/sda2 rw\n\
                    40 10 8:2 /c1 /alias rw - ext4 /dev/sda2 rw\n\
                    50 10 8:3 / /other rw - ext4 /dev/sda3 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state_id = fs_identity(&mounts, 20, "/state").expect("state");
        let children = mounts_under(&mounts, "/state");
        assert_eq!(children.len(), 1);
        assert!(source_reaches_protected(
            &mounts, 40, "/alias", true, &state_id, &children
        ));
        assert!(!source_reaches_protected(
            &mounts, 50, "/other", true, &state_id, &children
        ));
        // 子マウントを考慮しない（状態ルートだけの）照合では見逃していた。
        assert!(!source_reaches_protected(
            &mounts,
            40,
            "/alias",
            true,
            &state_id,
            &[]
        ));
        // 位置を特定できない元は fail-closed。
        assert!(source_reaches_protected(
            &mounts, 99, "/x", true, &state_id, &children
        ));
    }
}
