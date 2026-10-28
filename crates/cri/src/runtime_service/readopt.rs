//! 起動時の sandbox 記録の再採用（R6 #2935。CRI-1・CRI-2・REPAIR-4・REPAIR-5・SEC-5。設計は
//! `docs/design/cri-record-readoption.md`）。
//!
//! 役割: plugin-cri の再起動で失われた `SandboxRegistry` を、記録ストア（`with_record_store` で注入）の
//! sandbox 記録から復元する。呼び出し元は plugin-cri の `serve` が受付を始める前に 1 回だけ呼ぶ想定
//! （本番の配線と stderr への要約行の出力は R9 #2938）。呼び先は [`RecordStore::list`] と `record` の
//! 厳密な復号だけで、実行層・`PodNetworkProvider` は呼ばない。
//!
//! 契約:
//! - **副作用なし**: 記録のファイルを書き換えず、消さない（壊れた記録も残す。手動回収は R10）。次の Stop・Remove が
//!   確定版を書く・消す
//! - **registry が空であること**: 空でなければ `FAILED_PRECONDITION`。件数・保持量の上限超過や列挙の失敗・期限切れは
//!   起動を失敗させ、registry は空のまま（途中までの登録を残さない）
//! - **期限（REPAIR-5）**: 1 件ごとの読み取りと列挙全体の期限は [`ListBudget`]（ストア側）。復号後に全体の期限を再確認する
//! - **計測（REPAIR-4）**: `cri.record_store_load` の標本を、採用 1 件ごとに成功、壊れた記録 1 件ごとに失敗で出す。
//!   ID・パス・config・errno は渡さない
//!
//! 再採用した sandbox の値（保持役は再起動で終了しているため常に `NotReady`）:
//!
//! | 記録 | 登録する値 |
//! | ---- | ---------- |
//! | `pending=0` かつ `network_pending=0` | `NotReady`、`network_owned` は記録どおり、`network_pending=false` |
//! | `pending=1` または `network_pending=1` | `NotReady`、`network_pending=false`、`network_owned=true`（回収待ち） |
//!
//! `pending=1` は v1 では保持役の素性も `pod_netns` も記録に無く「副作用が無かった」と確認できないため、記録を
//! 破棄せず回収待ちへ倒す（fail-closed）。再採用した記録の pid から namespace のパスを作らず、シグナルも送らない
//! （SEC-5・#2776。v1 の記録に pid の鍵は無い）。
//!
//! # コンテナ記録の再採用と core の状態との照合（R7 #2936。CRI-1・OCI-7・CORE-1）
//!
//! [`CriRuntimeService::readopt_containers`] は [`CriRuntimeService::readopt_sandboxes`] の後に 1 回だけ呼び、
//! コンテナ記録のうち所属 sandbox を再採用できたものだけを登録する。core の状態は `RuntimeAdapter::state`
//! （`ContainerRuntime::state` → `StateStore::get`）を **記録にある ID だけ** 1 件ずつ期限つきで照会して得る。
//! CRI 記録の無い core のコンテナには触れない（照会もしない。SEC-1）。核となる写像は純粋関数 `reconcile`
//! （15 セルを 1 か所に集める）。core の応答は次のとおり 3 値に写す（`CorePresence`）。
//!
//! - Present: 状態を返した。Absent: `NOT_FOUND` だけ。Undetermined: それ以外（`INTERNAL`・ID 不一致・
//!   `DEADLINE_EXCEEDED`・`UNAVAILABLE`・`PERMISSION_DENIED`・`UNIMPLEMENTED`・1 件の期限切れ・実行層未注入）
//!
//! | CRI 記録 | core | 登録する状態 | `runtime_owned` |
//! | -------- | ---- | ------------ | --------------- |
//! | 確定 / in_flight=start / stop | Present | core の lifecycle を写す（Created→created・Running→running・Stopped→exited・その他→unknown） | true |
//! | 確定 / in_flight=start / stop | Absent | exited（終了コード・時刻は記録の値） | false |
//! | in_flight=create | Present | unknown（再 Start は拒否） | true |
//! | in_flight=create | Absent | 登録しない（`stale_create`。消去は R8 #2937 の `release_stale_creates`） | - |
//! | in_flight=remove | Present | unknown（Remove の続き待ち） | true |
//! | in_flight=remove | Absent | unknown（Remove の続き待ち。`remove_pending`） | true |
//! | 任意 | Undetermined | unknown（`CONTAINER_UNKNOWN`。何も消さない） | true |
//!
//! 登録する記録はどれも `in_flight=false`。in_flight=remove × Absent を `runtime_owned=true` にするのは、偽だと
//! kubelet の再試行がメモリ上の除去だけになり、記録ファイルと bundle が残るため（真なら `delete` の `NOT_FOUND`
//! を許容して release → 記録の削除まで進める）。in_flight=start / stop × Absent は v1 の R5 が書かない組だが、
//! 復号器は受理するため確定 × Absent と同じに扱う。
//!
//! 副作用なし: 呼ぶのは `state` だけで、`delete`・`stop`・`kill`・`start`・`RecordStore::put` / `remove`・
//! `BundleProvider::release` は呼ばない。registry の `Mutex` を持ったまま照会しない（ロック順序は registry > core）。
//!
//! # R8 #2937: bundle の release と記録の回収
//!
//! - `stale_create`: [`CriRuntimeService::release_stale_creates`] が `readopt_containers` の直後に 1 回、core を再照会して
//!   `NOT_FOUND` のときだけ `BundleProvider::release` → `RecordStore::remove` の順で消す（記録は所有の証明なので最後）。
//! - 確定 × core に無い（`runtime_owned=false`）: 実行層接続時にこの組が生じるのは再採用だけ（Create の巻き戻しは記録を
//!   消すか `runtime_owned=true` にする）。`RemoveContainer` / `RemovePodSandbox` が core の `delete` を呼ばずに bundle の
//!   解放と記録ファイルの削除まで行う（`runtime_remove_one` の `call_core=false`）。
//! - 孤児 bundle（CRI 記録が無く core にも無い `.cri/bundles/<id>`）の回収は、インスタンスロックの型が要るため plugin-cri の
//!   `orphan_bundles`。core の照会の写し方は [`probe_core_presence`] を共有する。
//!
//! 呼び出し順（R9 #2938 が受付の開始前に配線する）: `readopt_sandboxes` → `readopt_containers` → `release_stale_creates`
//! → 孤児 bundle の回収。解放に失敗した `stale_create` の記録が残る間はその bundle が孤児扱いにならないため、この順が要る。
//!
//! 未実装（REPAIR-3）: 保持役の素性による pending の解決は R11 #2940、`pod_netns`・provider 識別子の永続と再起動後の
//! `tear_down` は R12 #2941、本番の配線は R9 #2938、手動回収の手順は R10 #2939。

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tonic::Code;

use super::container::{ContainerRecord, ContainerState};
use super::record::{ContainerRecordData, SandboxRecordData};
use super::{
    CriRuntimeService, InFlightKind, ListBudget, ListLimits, ListedRecord, RecordId, RecordKind,
    RecordReadFailure, SandboxRecord, SandboxState, call_with_deadline, identity_retained_extra,
};
use crate::adapter::{RuntimeAdapter, RuntimeLifecycle};
use crate::error::{CriError, CriErrorCode};
use crate::instrument::{CriOpKind, CriOpSample};

/// 壊れた記録の内訳（件数のみ。ID・パスは持たない。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct BrokenRecordCounts {
    /// 復号に失敗した（版・鍵順・config・ファイル名と記録内 ID の不一致を含む）。
    pub malformed: usize,
    /// 通常ファイルでない（ディレクトリ・symlink・FIFO 等）。
    pub not_regular_file: usize,
    /// 1 件の長さの上限を超えた。
    pub too_long: usize,
    /// 権限・I/O エラーで読めない。
    pub unreadable: usize,
    /// 名前が ID として不正な `.rec`。
    pub unrecognized: usize,
    /// 他の記録と metadata（name・namespace・uid・attempt）が重複した（ID の小さい方を採り、残りは登録しない）。
    pub duplicate_metadata: usize,
    /// 所属 sandbox が再採用した registry に無い（コンテナ記録のみ。登録も削除もしない。R7）。
    pub parentless: usize,
}

impl BrokenRecordCounts {
    /// 壊れた記録の合計。
    pub fn total(&self) -> usize {
        self.malformed
            + self.not_regular_file
            + self.too_long
            + self.unreadable
            + self.unrecognized
            + self.duplicate_metadata
            + self.parentless
    }
}

/// [`CriRuntimeService::readopt_sandboxes`] の結果（REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SandboxReadoption {
    /// registry へ戻した sandbox の件数。
    pub adopted: usize,
    /// 作成途中・pod network 設定中の印があり、回収待ち（`network_owned=true`）へ倒した件数。
    pub pending_unresolved: usize,
    /// 登録しなかった壊れた記録の内訳。
    pub broken: BrokenRecordCounts,
}

impl SandboxReadoption {
    /// 固定語彙の 1 行要約（ID・パス・config を含めない）。stderr への出力は R9 #2938 が行う。
    pub fn summary_line(&self) -> String {
        format!(
            "cri record readoption: kind=sandbox adopted={} pending_unresolved={} broken={} malformed={} not_regular_file={} too_long={} unreadable={} unrecognized={} duplicate_metadata={}",
            self.adopted,
            self.pending_unresolved,
            self.broken.total(),
            self.broken.malformed,
            self.broken.not_regular_file,
            self.broken.too_long,
            self.broken.unreadable,
            self.broken.unrecognized,
            self.broken.duplicate_metadata,
        )
    }
}

/// [`CriRuntimeService::readopt_containers`] の結果（REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ContainerReadoption {
    /// registry へ戻したコンテナの件数（`present` + `absent_exited` + `remove_pending` + `undetermined`）。
    pub adopted: usize,
    /// core に状態があり、その lifecycle（または unknown）で戻した件数。
    pub present: usize,
    /// core に無く、記録の値で exited（`runtime_owned=false`）にした件数。
    pub absent_exited: usize,
    /// in_flight=remove で core に無く、Remove の続き待ち（unknown・`runtime_owned=true`）にした件数。
    pub remove_pending: usize,
    /// core の状態を確定できず `CONTAINER_UNKNOWN` で保持した件数。
    pub undetermined: usize,
    /// in_flight=create で core に無く、登録しなかった件数（記録と bundle の回収は R8 #2937）。
    pub stale_create: usize,
    /// 登録しなかった壊れた記録の内訳。
    pub broken: BrokenRecordCounts,
    stale_create_ids: Vec<String>,
}

impl ContainerReadoption {
    /// `stale_create` の ID（昇順）。R8 #2937 が「bundle の release → 記録の削除」の対象にする。
    pub fn stale_create_ids(&self) -> &[String] {
        &self.stale_create_ids
    }

    /// 固定語彙の 1 行要約（ID・パス・config を含めない）。stderr への出力は R9 #2938 が行う。
    pub fn summary_line(&self) -> String {
        format!(
            "cri record readoption: kind=container adopted={} present={} absent_exited={} remove_pending={} undetermined={} stale_create={} broken={} malformed={} not_regular_file={} too_long={} unreadable={} unrecognized={} duplicate_metadata={} parentless={}",
            self.adopted,
            self.present,
            self.absent_exited,
            self.remove_pending,
            self.undetermined,
            self.stale_create,
            self.broken.total(),
            self.broken.malformed,
            self.broken.not_regular_file,
            self.broken.too_long,
            self.broken.unreadable,
            self.broken.unrecognized,
            self.broken.duplicate_metadata,
            self.broken.parentless,
        )
    }
}

/// core の状態の照会結果（`RuntimeAdapter::state` の応答を 3 値に写したもの。R7 #2936・R8 #2937）。
///
/// 写し方は [`probe_core_presence`] の 1 か所に集め、コンテナ記録の再採用（R7）・`stale_create` の解放・孤児 bundle の
/// 回収（plugin-cri。R8）が共有する。消してよいのは [`Self::Absent`] のときだけ（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorePresence {
    /// 状態を返した。
    Present(RuntimeLifecycle),
    /// `NOT_FOUND` だけ。
    Absent,
    /// それ以外の失敗（`INTERNAL`・ID 不一致・`DEADLINE_EXCEEDED`・`UNAVAILABLE`・`PERMISSION_DENIED`・
    /// `UNIMPLEMENTED`）・期限切れ・実行層未注入。
    Undetermined,
}

/// core の状態を 1 件照会し 3 値に写す（`state` だけを呼ぶ。期限は `timeout`。REPAIR-5）。
///
/// 期限を超えたら [`CorePresence::Undetermined`] にし、呼び出しは切り離したスレッドで走り続ける。
pub fn probe_core_presence(adapter: &RuntimeAdapter, id: &str, timeout: Duration) -> CorePresence {
    let adapter = adapter.clone();
    let id = id.to_owned();
    match call_with_deadline(timeout, move || adapter.state(&id)) {
        Some(Ok(status)) => CorePresence::Present(status.lifecycle),
        Some(Err(e)) if e.code() == CriErrorCode::NotFound => CorePresence::Absent,
        _ => CorePresence::Undetermined,
    }
}

/// [`CriRuntimeService::release_stale_creates`] の結果（REPAIR-4。件数のみ。ID・パスは持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StaleCreateRelease {
    /// bundle の解放と記録の削除を終えた件数。
    pub released: usize,
    /// 再照会で core に無いと確認できず、何もしなかった件数（Present・Undetermined）。
    pub kept: usize,
    /// bundle の解放に失敗（期限切れを含む）し、記録も残した件数（次回起動で再び拾われる）。
    pub release_failed: usize,
    /// bundle は解放したが記録の削除に失敗（期限切れを含む）した件数（記録が残り次回起動で再試行される）。
    pub record_remove_failed: usize,
    /// 全体の期限を超えて試みなかった件数。
    pub not_attempted: usize,
    /// 記録ストアまたは実行層が未注入で何もしなかった件数。
    pub skipped: usize,
}

impl StaleCreateRelease {
    /// 固定語彙の 1 行要約（ID・パスを含めない）。stderr への出力は R9 #2938 が行う。
    pub fn summary_line(&self) -> String {
        format!(
            "cri stale create release: released={} kept={} release_failed={} record_remove_failed={} not_attempted={} skipped={}",
            self.released,
            self.kept,
            self.release_failed,
            self.record_remove_failed,
            self.not_attempted,
            self.skipped,
        )
    }
}

/// 照合の計上先。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Present,
    AbsentExited,
    RemovePending,
    Undetermined,
}

/// 照合結果（登録する状態と `runtime_owned`。登録しないものは `StaleCreate`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    StaleCreate,
    Register {
        state: ContainerState,
        runtime_owned: bool,
        bucket: Bucket,
    },
}

fn state_of_lifecycle(l: RuntimeLifecycle) -> ContainerState {
    match l {
        RuntimeLifecycle::Created => ContainerState::Created,
        RuntimeLifecycle::Running => ContainerState::Running,
        RuntimeLifecycle::Stopped => ContainerState::Exited,
        _ => ContainerState::Unknown,
    }
}

/// CRI 記録の `in_flight` と core の状態から、再採用後の状態と `runtime_owned` を決める（モジュール doc の表）。
fn reconcile(in_flight: Option<InFlightKind>, probe: CorePresence) -> Outcome {
    use InFlightKind::{Create, Remove};
    let register = |state, runtime_owned, bucket| Outcome::Register {
        state,
        runtime_owned,
        bucket,
    };
    match (in_flight, probe) {
        (_, CorePresence::Undetermined) => {
            register(ContainerState::Unknown, true, Bucket::Undetermined)
        }
        (Some(Create), CorePresence::Absent) => Outcome::StaleCreate,
        (Some(Create | Remove), CorePresence::Present(_)) => {
            register(ContainerState::Unknown, true, Bucket::Present)
        }
        (Some(Remove), CorePresence::Absent) => {
            register(ContainerState::Unknown, true, Bucket::RemovePending)
        }
        (_, CorePresence::Present(l)) => register(state_of_lifecycle(l), true, Bucket::Present),
        (_, CorePresence::Absent) => register(ContainerState::Exited, false, Bucket::AbsentExited),
    }
}

fn same_metadata(a: &SandboxRecord, b: &SandboxRecord) -> bool {
    match (a.config.metadata.as_ref(), b.config.metadata.as_ref()) {
        (Some(x), Some(y)) => {
            x.name == y.name
                && x.namespace == y.namespace
                && x.uid == y.uid
                && x.attempt == y.attempt
        }
        _ => false,
    }
}

impl CriRuntimeService {
    /// 記録ストアの sandbox 記録を registry へ戻す（R6 #2935。CRI-2）。受付を始める前に 1 回だけ呼ぶ。
    ///
    /// 記録ストア未注入なら何もせず件数 0 を返す。registry が空でなければ `FAILED_PRECONDITION`。
    /// 列挙の失敗・件数または保持量の上限超過（壊れた記録も件数・走査数に数えられる。意図した fail-closed）・
    /// 期限切れでは起動を失敗させ、registry は変えない。モジュール doc の契約を参照。
    pub fn readopt_sandboxes(&self, budget: ListBudget) -> Result<SandboxReadoption, CriError> {
        let Some(store) = self.record_store.as_ref() else {
            return Ok(SandboxReadoption::default());
        };
        {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if !registry.records.is_empty() || !registry.containers.is_empty() {
                return Err(CriError::failed_precondition(
                    "sandbox registry is not empty",
                ));
            }
        }
        let start = Instant::now();
        let limits = ListLimits::for_kind(RecordKind::Sandbox)
            .with_max_records(RecordKind::Sandbox, self.limits.max_sandboxes());
        let mut listing = match store.list(RecordKind::Sandbox, budget, limits) {
            Ok(l) => l,
            Err(e) => {
                self.record_load(e.code().grpc_code(), start);
                return Err(e);
            }
        };
        listing.records.sort_by(|a, b| a.id.cmp(&b.id));

        let mut result = SandboxReadoption::default();
        result.broken.unrecognized = listing.unrecognized;
        for _ in 0..listing.unrecognized {
            self.record_load(Code::DataLoss, Instant::now());
        }
        let mut accepted: Vec<(String, SandboxRecord)> = Vec::new();
        for ListedRecord { id, outcome } in listing.records {
            let one = Instant::now();
            let bytes = match outcome {
                Ok(b) => b,
                Err(RecordReadFailure::NotRegularFile) => {
                    result.broken.not_regular_file += 1;
                    self.record_load(Code::DataLoss, one);
                    continue;
                }
                Err(RecordReadFailure::TooLong) => {
                    result.broken.too_long += 1;
                    self.record_load(Code::DataLoss, one);
                    continue;
                }
                Err(_) => {
                    result.broken.unreadable += 1;
                    self.record_load(Code::DataLoss, one);
                    continue;
                }
            };
            let decoded = match SandboxRecordData::decode(&bytes, id.as_str()) {
                Ok(d) => d,
                Err(_) => {
                    result.broken.malformed += 1;
                    self.record_load(Code::InvalidArgument, one);
                    continue;
                }
            };
            let data = decoded.data;
            let unresolved = data.pending || data.network_pending;
            let record = SandboxRecord {
                config: data.config,
                state: SandboxState::NotReady,
                created_at_nanos: data.created_at_nanos,
                runtime_handler: data.runtime_handler,
                retained_bytes: decoded.retained_bytes,
                network_pending: false,
                network_owned: data.network_owned || unresolved,
                network_teardown: false,
                pod_netns: None,
                record_write: 0,
            };
            if accepted.iter().any(|(_, r)| same_metadata(r, &record)) {
                result.broken.duplicate_metadata += 1;
                self.record_load(Code::InvalidArgument, one);
                continue;
            }
            if unresolved {
                result.pending_unresolved += 1;
            }
            accepted.push((id.as_str().to_owned(), record));
            self.record_load(Code::Ok, one);
        }

        if start.elapsed() >= budget.total {
            let e = CriError::timeout("sandbox record readoption timed out");
            self.record_load(e.code().grpc_code(), start);
            return Err(e);
        }
        let total = accepted
            .iter()
            .try_fold(0usize, |acc, (_, r)| acc.checked_add(r.retained_bytes));
        let over = accepted.len() > self.limits.max_sandboxes()
            || total.is_none_or(|t| t > self.limits.max_retained_bytes());
        if over {
            let e = CriError::failed_precondition("sandbox records exceed the configured limits");
            self.record_load(e.code().grpc_code(), start);
            return Err(e);
        }
        result.adopted = accepted.len();
        {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if !registry.records.is_empty() || !registry.containers.is_empty() {
                return Err(CriError::failed_precondition(
                    "sandbox registry is not empty",
                ));
            }
            registry.retained_bytes = total.unwrap_or(0);
            registry.records.extend(accepted);
        }
        Ok(result)
    }

    /// 記録ストアのコンテナ記録を registry へ戻し、core の状態で照合する（R7 #2936。CRI-1・OCI-7・CORE-1）。
    ///
    /// [`Self::readopt_sandboxes`] の後に 1 回だけ呼ぶ。記録ストア未注入なら何もせず件数 0。コンテナの registry が
    /// 空でなければ `FAILED_PRECONDITION`。所属 sandbox が registry に無い記録は壊れた記録として数える。
    /// core の照会は `with_runtime` で注入した実行層の `state` だけで、未注入なら全件 unknown で保持する。
    /// 件数・保持量の上限超過と全体の期限切れは起動を失敗させ、registry は変えない。モジュール doc の契約と表を参照。
    pub fn readopt_containers(&self, budget: ListBudget) -> Result<ContainerReadoption, CriError> {
        let Some(store) = self.record_store.as_ref() else {
            return Ok(ContainerReadoption::default());
        };
        let parents: HashSet<String> = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if !registry.containers.is_empty() {
                return Err(CriError::failed_precondition(
                    "container registry is not empty",
                ));
            }
            registry.records.keys().cloned().collect()
        };
        let start = Instant::now();
        let limits = ListLimits::for_kind(RecordKind::Container).with_max_records(
            RecordKind::Container,
            self.container_limits.max_containers(),
        );
        let mut listing = match store.list(RecordKind::Container, budget, limits) {
            Ok(l) => l,
            Err(e) => {
                self.record_load(e.code().grpc_code(), start);
                return Err(e);
            }
        };
        listing.records.sort_by(|a, b| a.id.cmp(&b.id));

        let mut result = ContainerReadoption::default();
        result.broken.unrecognized = listing.unrecognized;
        for _ in 0..listing.unrecognized {
            self.record_load(Code::DataLoss, Instant::now());
        }
        let mut accepted: Vec<(String, ContainerRecord)> = Vec::new();
        let mut keys: HashSet<(String, String, u32)> = HashSet::new();
        let mut retained_total: usize = 0;
        for ListedRecord { id, outcome } in listing.records {
            // 読み取り失敗・復号失敗・親不在の分岐も含め、毎回先頭で全体期限を検査する（REPAIR-5）。
            if start.elapsed() >= budget.total {
                let e = CriError::timeout("container record readoption timed out");
                self.record_load(e.code().grpc_code(), start);
                return Err(e);
            }
            let one = Instant::now();
            let bytes = match outcome {
                Ok(b) => b,
                Err(RecordReadFailure::NotRegularFile) => {
                    result.broken.not_regular_file += 1;
                    self.record_load(Code::DataLoss, one);
                    continue;
                }
                Err(RecordReadFailure::TooLong) => {
                    result.broken.too_long += 1;
                    self.record_load(Code::DataLoss, one);
                    continue;
                }
                Err(_) => {
                    result.broken.unreadable += 1;
                    self.record_load(Code::DataLoss, one);
                    continue;
                }
            };
            let decoded = match ContainerRecordData::decode(&bytes, id.as_str()) {
                Ok(d) => d,
                Err(_) => {
                    result.broken.malformed += 1;
                    self.record_load(Code::InvalidArgument, one);
                    continue;
                }
            };
            let data = decoded.data;
            if !parents.contains(&data.pod_sandbox_id) {
                result.broken.parentless += 1;
                self.record_load(Code::DataLoss, one);
                continue;
            }
            let Some(metadata) = data.config.metadata.as_ref() else {
                result.broken.malformed += 1;
                self.record_load(Code::InvalidArgument, one);
                continue;
            };
            let key = (
                data.pod_sandbox_id.clone(),
                metadata.name.clone(),
                metadata.attempt,
            );
            let remaining = budget.total.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                let e = CriError::timeout("container record readoption timed out");
                self.record_load(e.code().grpc_code(), start);
                return Err(e);
            }
            let probe = self.probe_core(id.as_str(), budget.per_record.min(remaining));
            if start.elapsed() >= budget.total {
                let e = CriError::timeout("container record readoption timed out");
                self.record_load(e.code().grpc_code(), start);
                return Err(e);
            }
            let (state, runtime_owned, bucket) = match reconcile(data.in_flight, probe) {
                Outcome::StaleCreate => {
                    result.stale_create += 1;
                    result.stale_create_ids.push(id.as_str().to_owned());
                    self.record_load(Code::Ok, one);
                    continue;
                }
                Outcome::Register {
                    state,
                    runtime_owned,
                    bucket,
                } => (state, runtime_owned, bucket),
            };
            if !keys.insert(key) {
                result.broken.duplicate_metadata += 1;
                self.record_load(Code::InvalidArgument, one);
                continue;
            }
            let log_len = data
                .resolved_log_path
                .as_ref()
                .map_or(0, |p| p.as_str().len());
            let retained_bytes = decoded
                .retained_bytes
                .saturating_add(log_len)
                .saturating_add(identity_retained_extra(
                    data.applied_user.as_ref(),
                    data.resolved_image.as_ref(),
                ));
            // 復号後の保持量を逐次積算し、accepted へ載せる前に上限超過を拒否する（OOM 防止）。
            let next_total = retained_total.checked_add(retained_bytes);
            if accepted.len() >= self.container_limits.max_containers()
                || next_total.is_none_or(|t| t > self.container_limits.max_retained_bytes())
            {
                let e =
                    CriError::failed_precondition("container records exceed the configured limits");
                self.record_load(e.code().grpc_code(), start);
                return Err(e);
            }
            retained_total = next_total.unwrap_or(retained_total);
            match bucket {
                Bucket::Present => result.present += 1,
                Bucket::AbsentExited => result.absent_exited += 1,
                Bucket::RemovePending => result.remove_pending += 1,
                Bucket::Undetermined => result.undetermined += 1,
            }
            accepted.push((
                id.as_str().to_owned(),
                ContainerRecord {
                    pod_sandbox_id: data.pod_sandbox_id,
                    config: data.config,
                    state,
                    created_at_nanos: data.created_at_nanos,
                    started_at_nanos: data.started_at_nanos,
                    finished_at_nanos: data.finished_at_nanos,
                    exit_code: data.exit_code,
                    termination: data.termination,
                    retained_bytes,
                    resolved_log_path: data.resolved_log_path,
                    in_flight: false,
                    runtime_owned,
                    stop_signal: data.stop_signal,
                    applied_user: data.applied_user,
                    resolved_image: data.resolved_image,
                },
            ));
            self.record_load(Code::Ok, one);
        }

        // 登録前にも全体期限を検査する（期限切れは起動失敗で registry を変えない。REPAIR-5）。
        if start.elapsed() >= budget.total {
            let e = CriError::timeout("container record readoption timed out");
            self.record_load(e.code().grpc_code(), start);
            return Err(e);
        }
        result.adopted = accepted.len();
        {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if !registry.containers.is_empty() {
                return Err(CriError::failed_precondition(
                    "container registry is not empty",
                ));
            }
            registry.container_retained_bytes = retained_total;
            for (id, record) in accepted {
                if let Some(m) = record.config.metadata.as_ref() {
                    registry.container_keys.insert((
                        record.pod_sandbox_id.clone(),
                        m.name.clone(),
                        m.attempt,
                    ));
                }
                registry.containers.insert(id, record);
            }
        }
        Ok(result)
    }

    /// core の状態を 1 件照会する（実行層未注入は結果不明）。
    fn probe_core(&self, id: &str, timeout: Duration) -> CorePresence {
        match self.runtime.as_ref() {
            Some(binding) => probe_core_presence(&binding.adapter, id, timeout),
            None => CorePresence::Undetermined,
        }
    }

    /// `readopt_containers` が登録しなかった `stale_create`（in_flight=create で core に無い記録）の bundle を解放し、
    /// 記録ファイルを消す（R8 #2937。OCI-7・CRI-1・SEC-1・REPAIR-5）。
    ///
    /// `readopt_containers` の直後に 1 回だけ呼ぶ（受付開始前。常駐ループは作らない。CORE-1）。1 件ごとに core を
    /// 再照会し、`NOT_FOUND` だけのときに限り `BundleProvider::release` → `RecordStore::remove` の順で進める
    /// （所有の証明である記録は最後に消す）。再照会が Present・Undetermined なら何もしない。解放・記録の削除の失敗と
    /// 期限切れは件数に数えるだけで `Err` にしない（余分に残す側に倒す。記録が残るので次回起動で再び拾われ、
    /// release は不在を成功とするため冪等）。registry には触れない。`Err` は registry 汚染の前提違反のみ。
    pub fn release_stale_creates(
        &self,
        readoption: &ContainerReadoption,
        budget: ListBudget,
    ) -> Result<StaleCreateRelease, CriError> {
        let mut result = StaleCreateRelease::default();
        let ids = readoption.stale_create_ids();
        if ids.is_empty() {
            return Ok(result);
        }
        let (Some(store), Some(binding)) = (self.record_store.as_ref(), self.runtime.as_ref())
        else {
            result.skipped = ids.len();
            return Ok(result);
        };
        {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            // 登録済みの ID は stale_create ではない（呼び出しの前提違反。何も消さない）。
            if ids.iter().any(|id| registry.containers.contains_key(id)) {
                return Err(CriError::failed_precondition(
                    "stale create id is registered in the container registry",
                ));
            }
        }
        let start = Instant::now();
        for (index, id) in ids.iter().enumerate() {
            let remaining = budget.total.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                result.not_attempted = ids.len() - index;
                break;
            }
            let per = budget.per_record.min(remaining);
            if probe_core_presence(&binding.adapter, id, per) != CorePresence::Absent {
                result.kept += 1;
                continue;
            }
            // 各段階の直前に全体期限の残りを再計算する。尽きていれば新たな処理を始めない（REPAIR-5）。
            let remaining = budget.total.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                result.not_attempted = ids.len() - index;
                break;
            }
            let bundles = Arc::clone(&binding.bundles);
            let release_id = id.clone();
            let released = call_with_deadline(budget.per_record.min(remaining), move || {
                bundles.release(&release_id)
            });
            if !matches!(released, Some(Ok(()))) {
                result.release_failed += 1;
                continue;
            }
            let Ok(record_id) = RecordId::new(id) else {
                result.record_remove_failed += 1;
                continue;
            };
            let remaining = budget.total.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                // bundle は解放済みで記録だけ残る。次回起動で再び拾われ release は冪等。
                result.record_remove_failed += 1;
                result.not_attempted = ids.len() - index - 1;
                break;
            }
            let store = Arc::clone(store);
            let removed = call_with_deadline(budget.per_record.min(remaining), move || {
                store.remove(RecordKind::Container, &record_id)
            });
            if matches!(removed, Some(Ok(()))) {
                result.released += 1;
            } else {
                result.record_remove_failed += 1;
            }
        }
        Ok(result)
    }

    fn record_load(&self, code: Code, started: Instant) {
        self.recorder.record_cri_op(&CriOpSample::new(
            CriOpKind::RecordStoreLoad,
            code,
            started.elapsed(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::super::record::SandboxRecordData;
    use super::super::{
        CriRuntimeService, ListBudget, ListLimits, ListedRecord, RecordId, RecordKind,
        RecordListing, RecordReadFailure, RecordStore, SandboxLimits, SandboxState,
    };
    use crate::error::CriError;
    use crate::instrument::{CriOpKind, CriOpRecorder, CriOpSample};
    use crate::runtime::v1::{PodSandboxConfig, PodSandboxMetadata};
    use tonic::Code;

    fn id(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn data(c: char, name: &str) -> SandboxRecordData {
        SandboxRecordData {
            id: id(c),
            config: PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: name.into(),
                    uid: "uid".into(),
                    namespace: "ns".into(),
                    attempt: 1,
                }),
                labels: BTreeMap::from([("app".to_owned(), "web".to_owned())]),
                ..Default::default()
            },
            state: SandboxState::Ready,
            created_at_nanos: 1_700_000_000_000_000_001,
            runtime_handler: "",
            pending: false,
            network_owned: false,
            network_pending: false,
        }
    }

    fn ok(d: &SandboxRecordData) -> ListedRecord {
        ListedRecord {
            id: RecordId::new(&d.id).unwrap(),
            outcome: Ok(d.encode().unwrap()),
        }
    }

    #[derive(Debug, Default)]
    struct Fake {
        listing: Mutex<Option<Result<RecordListing, CriError>>>,
        calls: Mutex<(usize, usize)>,
        delay: Duration,
    }

    impl Fake {
        fn with(records: Vec<ListedRecord>, unrecognized: usize) -> Arc<Self> {
            Arc::new(Self {
                listing: Mutex::new(Some(Ok(RecordListing {
                    records,
                    unrecognized,
                }))),
                ..Default::default()
            })
        }
        fn failing(e: CriError) -> Arc<Self> {
            Arc::new(Self {
                listing: Mutex::new(Some(Err(e))),
                ..Default::default()
            })
        }
    }

    impl RecordStore for Fake {
        fn put(&self, _: RecordKind, _: &RecordId, _: &[u8]) -> Result<(), CriError> {
            self.calls.lock().unwrap().0 += 1;
            Ok(())
        }
        fn remove(&self, _: RecordKind, _: &RecordId) -> Result<(), CriError> {
            self.calls.lock().unwrap().1 += 1;
            Ok(())
        }
        fn list(
            &self,
            _: RecordKind,
            _: ListBudget,
            _: ListLimits,
        ) -> Result<RecordListing, CriError> {
            std::thread::sleep(self.delay);
            self.listing.lock().unwrap().take().unwrap()
        }
    }

    #[derive(Default)]
    struct Rec(Mutex<Vec<CriOpSample>>);
    impl CriOpRecorder for Rec {
        fn record_cri_op(&self, s: &CriOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    fn svc(store: Arc<Fake>, rec: Arc<Rec>) -> CriRuntimeService {
        CriRuntimeService::with_recorder(rec).with_record_store(store)
    }

    fn load_codes(rec: &Rec) -> Vec<Code> {
        rec.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.kind() == CriOpKind::RecordStoreLoad)
            .map(|s| s.code())
            .collect()
    }

    fn snapshot(s: &CriRuntimeService) -> Vec<(String, SandboxState, bool, bool)> {
        let r = s.registry.lock().unwrap();
        let mut v: Vec<_> = r
            .records
            .iter()
            .map(|(k, v)| (k.clone(), v.state, v.network_owned, v.network_pending))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// CRI-2: ready・確定の記録は NotReady で戻り、保持量は復号の値と一致する。
    #[test]
    fn cri2_readopt_ready_record_becomes_notready() {
        let d = data('a', "p");
        let store = Fake::with(vec![ok(&d)], 0);
        let rec = Arc::new(Rec::default());
        let s = svc(store.clone(), rec.clone());
        let r = s.readopt_sandboxes(ListBudget::default()).unwrap();
        assert_eq!(
            (r.adopted, r.pending_unresolved, r.broken.total()),
            (1, 0, 0)
        );
        assert_eq!(
            snapshot(&s),
            vec![(id('a'), SandboxState::NotReady, false, false)]
        );
        let reg = s.registry.lock().unwrap();
        let got = reg.records.get(&id('a')).unwrap();
        assert_eq!(got.created_at_nanos, 1_700_000_000_000_000_001);
        assert_eq!(
            got.config.labels.get("app").map(String::as_str),
            Some("web")
        );
        assert!(got.pod_netns.is_none());
        assert_eq!(got.record_write, 0);
        assert_eq!(reg.retained_bytes, got.retained_bytes);
        assert_eq!(*store.calls.lock().unwrap(), (0, 0));
        assert_eq!(load_codes(&rec), vec![Code::Ok]);
    }

    /// CRI-2: network_owned は引き継ぐ。
    #[test]
    fn cri2_readopt_keeps_network_owned() {
        let mut d = data('a', "p");
        d.network_owned = true;
        let s = svc(Fake::with(vec![ok(&d)], 0), Arc::default());
        s.readopt_sandboxes(ListBudget::default()).unwrap();
        assert_eq!(
            snapshot(&s),
            vec![(id('a'), SandboxState::NotReady, true, false)]
        );
    }

    /// CRI-2: provider 未注入では、回収待ちの再採用記録を Stop・Remove が成功させず、記録（メモリと永続）を保持する。
    #[test]
    fn cri2_readopt_owned_record_survives_remove_without_provider() {
        let mut d = data('a', "p");
        d.network_owned = true;
        let store = Fake::with(vec![ok(&d)], 0);
        let s = svc(store.clone(), Arc::default());
        s.readopt_sandboxes(ListBudget::default()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let rm = rt.block_on(s.remove_sandbox_with_network(
            crate::runtime::v1::RemovePodSandboxRequest {
                pod_sandbox_id: id('a'),
            },
        ));
        let stop = rt.block_on(s.stop_sandbox_with_network(
            crate::runtime::v1::StopPodSandboxRequest {
                pod_sandbox_id: id('a'),
            },
        ));
        for e in [rm.unwrap_err(), stop.unwrap_err()] {
            assert_eq!(e.code().grpc_code(), Code::FailedPrecondition);
        }
        assert_eq!(
            snapshot(&s),
            vec![(id('a'), SandboxState::NotReady, true, false)]
        );
        assert_eq!(*store.calls.lock().unwrap(), (0, 0));
    }

    /// CRI-2: pending / network_pending は回収待ち（network_owned=true）へ正規化し、ファイルに触れない。
    #[test]
    fn cri2_readopt_normalizes_pending_to_reclaimable() {
        let mut a = data('a', "p1");
        a.pending = true;
        a.network_pending = true;
        let mut b = data('b', "p2");
        b.network_pending = true;
        let store = Fake::with(vec![ok(&a), ok(&b)], 0);
        let s = svc(store.clone(), Arc::default());
        let r = s.readopt_sandboxes(ListBudget::default()).unwrap();
        assert_eq!((r.adopted, r.pending_unresolved), (2, 2));
        assert_eq!(
            snapshot(&s),
            vec![
                (id('a'), SandboxState::NotReady, true, false),
                (id('b'), SandboxState::NotReady, true, false),
            ]
        );
        assert_eq!(*store.calls.lock().unwrap(), (0, 0));
    }

    /// CRI-2・REPAIR-4: 壊れた記録は登録せず、内訳と記録器の失敗に計上する。
    #[test]
    fn cri2_repair4_broken_records_are_counted_not_registered() {
        let good = data('a', "p");
        let other = data('c', "q");
        let mismatch = ListedRecord {
            id: RecordId::new(&id('d')).unwrap(),
            outcome: Ok(other.encode().unwrap()),
        };
        let records = vec![
            ok(&good),
            ListedRecord {
                id: RecordId::new(&id('b')).unwrap(),
                outcome: Ok(b"garbage".to_vec()),
            },
            mismatch,
            ListedRecord {
                id: RecordId::new(&id('e')).unwrap(),
                outcome: Err(RecordReadFailure::TooLong),
            },
            ListedRecord {
                id: RecordId::new(&id('f')).unwrap(),
                outcome: Err(RecordReadFailure::NotRegularFile),
            },
            ListedRecord {
                id: RecordId::new(&id('1')).unwrap(),
                outcome: Err(RecordReadFailure::Unreadable),
            },
        ];
        let store = Fake::with(records, 2);
        let rec = Arc::new(Rec::default());
        let s = svc(store.clone(), rec.clone());
        let r = s.readopt_sandboxes(ListBudget::default()).unwrap();
        assert_eq!(r.adopted, 1);
        assert_eq!(r.broken.malformed, 2);
        assert_eq!(r.broken.too_long, 1);
        assert_eq!(r.broken.not_regular_file, 1);
        assert_eq!(r.broken.unreadable, 1);
        assert_eq!(r.broken.unrecognized, 2);
        assert_eq!(r.broken.total(), 7);
        assert_eq!(snapshot(&s).len(), 1);
        assert_eq!(*store.calls.lock().unwrap(), (0, 0));
        let codes = load_codes(&rec);
        assert_eq!(codes.iter().filter(|c| **c == Code::Ok).count(), 1);
        assert_eq!(
            codes
                .iter()
                .filter(|c| **c == Code::InvalidArgument)
                .count(),
            2
        );
        assert_eq!(codes.iter().filter(|c| **c == Code::DataLoss).count(), 5);
    }

    /// CRI-2: metadata が重複する記録は ID の小さい方だけ登録する。
    #[test]
    fn cri2_readopt_duplicate_metadata_keeps_smaller_id() {
        let a = data('a', "same");
        let b = data('b', "same");
        let s = svc(Fake::with(vec![ok(&b), ok(&a)], 0), Arc::default());
        let r = s.readopt_sandboxes(ListBudget::default()).unwrap();
        assert_eq!((r.adopted, r.broken.duplicate_metadata), (1, 1));
        assert_eq!(snapshot(&s)[0].0, id('a'));
    }

    /// CRI-2・REPAIR-5: 上限超過は起動を失敗させ、registry は空のまま。
    #[test]
    fn cri2_readopt_over_limits_fails_closed() {
        let store = Fake::with(vec![ok(&data('a', "p")), ok(&data('b', "q"))], 0);
        let s = CriRuntimeService::with_limits_and_recorder(
            SandboxLimits::new().with_max_sandboxes(1),
            Arc::new(crate::instrument::NoopCriOpRecorder),
        )
        .with_record_store(store);
        let e = s.readopt_sandboxes(ListBudget::default()).unwrap_err();
        assert_eq!(e.code().grpc_code(), Code::FailedPrecondition);
        assert!(snapshot(&s).is_empty());

        let store = Fake::with(vec![ok(&data('a', "p"))], 0);
        let s = CriRuntimeService::with_limits_and_recorder(
            SandboxLimits::new().with_max_retained_bytes(1),
            Arc::new(crate::instrument::NoopCriOpRecorder),
        )
        .with_record_store(store);
        let e = s.readopt_sandboxes(ListBudget::default()).unwrap_err();
        assert_eq!(e.code().grpc_code(), Code::FailedPrecondition);
        assert!(snapshot(&s).is_empty());
        assert_eq!(s.registry.lock().unwrap().retained_bytes, 0);
    }

    /// REPAIR-5: ストアの列挙失敗は同じコードで失敗し、全体の期限切れは DEADLINE_EXCEEDED。
    #[test]
    fn repair5_readopt_list_failure_and_total_deadline() {
        let rec = Arc::new(Rec::default());
        let s = svc(
            Fake::failing(CriError::failed_precondition("too many")),
            rec.clone(),
        );
        let e = s.readopt_sandboxes(ListBudget::default()).unwrap_err();
        assert_eq!(e.code().grpc_code(), Code::FailedPrecondition);
        assert_eq!(load_codes(&rec), vec![Code::FailedPrecondition]);

        let s = svc(Fake::failing(CriError::timeout("slow")), Arc::default());
        let e = s.readopt_sandboxes(ListBudget::default()).unwrap_err();
        assert_eq!(e.code().grpc_code(), Code::DeadlineExceeded);

        let store = Arc::new(Fake {
            listing: Mutex::new(Some(Ok(RecordListing {
                records: vec![ok(&data('a', "p"))],
                unrecognized: 0,
            }))),
            delay: Duration::from_millis(30),
            ..Default::default()
        });
        let s = svc(store, Arc::default());
        let budget = ListBudget {
            per_record: Duration::from_secs(1),
            total: Duration::from_millis(5),
        };
        let e = s.readopt_sandboxes(budget).unwrap_err();
        assert_eq!(e.code().grpc_code(), Code::DeadlineExceeded);
        assert!(snapshot(&s).is_empty());
    }

    /// 未注入は何もせず、registry が空でなければ拒否する。
    #[test]
    fn cri2_readopt_without_store_is_noop_and_requires_empty_registry() {
        let s = CriRuntimeService::new();
        let r = s.readopt_sandboxes(ListBudget::default()).unwrap();
        assert_eq!(r, super::SandboxReadoption::default());

        let s = svc(Fake::with(vec![ok(&data('a', "p"))], 0), Arc::default());
        s.readopt_sandboxes(ListBudget::default()).unwrap();
        let e = s.readopt_sandboxes(ListBudget::default()).unwrap_err();
        assert_eq!(e.code().grpc_code(), Code::FailedPrecondition);
    }

    /// REPAIR-4: 要約行は固定語彙で、ID を含まない。
    #[test]
    fn repair4_summary_line_is_fixed_vocabulary() {
        let s = svc(Fake::with(vec![ok(&data('a', "p"))], 1), Arc::default());
        let r = s.readopt_sandboxes(ListBudget::default()).unwrap();
        let line = r.summary_line();
        assert_eq!(
            line,
            "cri record readoption: kind=sandbox adopted=1 pending_unresolved=0 broken=1 malformed=0 not_regular_file=0 too_long=0 unreadable=0 unrecognized=1 duplicate_metadata=0"
        );
        assert!(!line.contains(&id('a')));
    }
    // ---- コンテナ記録の再採用と core の状態との照合（R7 #2936。CRI-1・OCI-7・CORE-1） ----

    use super::super::InFlightKind;
    use super::super::container::ContainerState;
    use super::super::record::ContainerRecordData;
    use super::{Bucket, CorePresence, Outcome, reconcile, state_of_lifecycle};
    use crate::adapter::{
        BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter, RuntimeLifecycle,
    };
    use crate::bundle::{AppliedUser, ResolvedImage};
    use crate::runtime::v1::{
        ContainerConfig, ContainerMetadata, ImageSpec, RemoveContainerRequest, Signal,
        StartContainerRequest, runtime_service_server::RuntimeService,
    };
    use fandhe_container_core::traits::{
        ContainerId, ContainerLogPath, ContainerRuntime, ContainerStatus, CreateRequest,
        DeleteRequest, DeleteResponse, ErrorCode, KillRequest, StartRequest, StateRequest,
        StopRequest, TraitError,
    };
    use fandhe_container_oci::reference::Digest;
    use std::collections::HashMap;

    /// 種別ごとの列挙を返す偽ストア（put / remove の回数を数える）。
    #[derive(Debug, Default)]
    struct KindStore {
        sandboxes: Mutex<Vec<ListedRecord>>,
        containers: Mutex<Vec<ListedRecord>>,
        calls: Mutex<(usize, usize)>,
        /// `remove` に渡された ID の順序（R8 #2937）。
        removed: Mutex<Vec<String>>,
        /// 真なら `remove` が失敗する（R8 #2937）。
        fail_remove: Mutex<bool>,
    }

    impl RecordStore for KindStore {
        fn put(&self, _: RecordKind, _: &RecordId, _: &[u8]) -> Result<(), CriError> {
            self.calls.lock().unwrap().0 += 1;
            Ok(())
        }
        fn remove(&self, _: RecordKind, id: &RecordId) -> Result<(), CriError> {
            self.calls.lock().unwrap().1 += 1;
            self.removed.lock().unwrap().push(id.as_str().to_owned());
            if *self.fail_remove.lock().unwrap() {
                return Err(CriError::internal("injected"));
            }
            Ok(())
        }
        fn list(
            &self,
            kind: RecordKind,
            _: ListBudget,
            _: ListLimits,
        ) -> Result<RecordListing, CriError> {
            let records = match kind {
                RecordKind::Sandbox => std::mem::take(&mut *self.sandboxes.lock().unwrap()),
                RecordKind::Container => std::mem::take(&mut *self.containers.lock().unwrap()),
            };
            Ok(RecordListing {
                records,
                unrecognized: 0,
            })
        }
    }

    #[derive(Clone, Copy)]
    enum Core {
        Created,
        Running,
        Stopped,
        Creating,
        Fail(ErrorCode),
        WrongId,
        Sleep(Duration),
    }

    /// core の偽。`state` は map にある ID だけに答え、無い ID は `NOT_FOUND`。呼ばれた操作を全て記録する。
    #[derive(Default)]
    struct FakeCore {
        states: Mutex<HashMap<String, Core>>,
        calls: Mutex<Vec<String>>,
    }

    struct SharedCore(Arc<FakeCore>);

    impl ContainerRuntime for SharedCore {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("create:{}", r.id()));
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("start:{}", r.id()));
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn kill(&self, r: &KillRequest) -> Result<ContainerStatus, TraitError> {
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("kill:{}", r.id()));
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("stop:{}", r.id()));
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("delete:{}", r.id()));
            if self.0.states.lock().unwrap().contains_key(r.id().as_str()) {
                Ok(DeleteResponse::new())
            } else {
                Err(TraitError::new(ErrorCode::NotFound, "gone"))
            }
        }
        fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("state:{}", r.id()));
            let known = self.0.states.lock().unwrap().get(r.id().as_str()).copied();
            let cid = r.id().clone();
            match known {
                None => Err(TraitError::new(ErrorCode::NotFound, "gone")),
                Some(Core::Created) => Ok(ContainerStatus::created(cid, None)),
                Some(Core::Running) => Ok(ContainerStatus::running(cid, None)),
                Some(Core::Stopped) => Ok(ContainerStatus::stopped(cid, Some(9))),
                Some(Core::Creating) => Ok(ContainerStatus::creating(cid)),
                Some(Core::Fail(c)) => Err(TraitError::new(c, "failed")),
                Some(Core::WrongId) => Ok(ContainerStatus::running(
                    ContainerId::new("f".repeat(64)).unwrap(),
                    None,
                )),
                Some(Core::Sleep(d)) => {
                    std::thread::sleep(d);
                    Ok(ContainerStatus::running(cid, None))
                }
            }
        }
    }

    /// 解放の回数（`.0`）・失敗の注入（`.1`）・解放した ID の順序（`.2`）を持つ bundle の偽。
    #[derive(Default)]
    struct CountBundles(Mutex<usize>, Mutex<bool>, Mutex<Vec<String>>);
    impl BundleProvider for CountBundles {
        fn prepare(&self, _: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
            Err(CriError::internal("unused"))
        }
        fn release(&self, id: &str) -> Result<(), CriError> {
            *self.0.lock().unwrap() += 1;
            self.2.lock().unwrap().push(id.to_owned());
            if *self.1.lock().unwrap() {
                return Err(CriError::internal("injected"));
            }
            Ok(())
        }
    }

    struct Env {
        svc: CriRuntimeService,
        store: Arc<KindStore>,
        core: Arc<FakeCore>,
        bundles: Arc<CountBundles>,
        rec: Arc<Rec>,
    }

    fn env_with(
        sandboxes: Vec<ListedRecord>,
        containers: Vec<ListedRecord>,
        core: &[(String, Core)],
        with_runtime: bool,
        build: impl FnOnce(CriRuntimeService) -> CriRuntimeService,
    ) -> Env {
        let store = Arc::new(KindStore {
            sandboxes: Mutex::new(sandboxes),
            containers: Mutex::new(containers),
            calls: Mutex::new((0, 0)),
            ..Default::default()
        });
        let fake = Arc::new(FakeCore::default());
        fake.states.lock().unwrap().extend(core.iter().cloned());
        let bundles = Arc::new(CountBundles::default());
        let rec = Arc::new(Rec::default());
        let mut svc =
            build(CriRuntimeService::with_recorder(rec.clone())).with_record_store(store.clone());
        if with_runtime {
            svc = svc.with_runtime(
                RuntimeAdapter::new(Arc::new(SharedCore(fake.clone()))),
                bundles.clone(),
            );
        }
        Env {
            svc,
            store,
            core: fake,
            bundles,
            rec,
        }
    }

    fn env(containers: Vec<ListedRecord>, core: &[(String, Core)]) -> Env {
        env_with(vec![ok(&data('a', "p"))], containers, core, true, |s| s)
    }

    fn digest() -> Digest {
        Digest::parse(&format!("sha256:{}", "ab".repeat(32))).unwrap()
    }

    const LOG: &str = "/var/log/pods/ns_p_uid/c/0.log";

    fn cdata(
        c: char,
        name: &str,
        in_flight: Option<InFlightKind>,
        state: ContainerState,
    ) -> ContainerRecordData {
        ContainerRecordData {
            id: id(c),
            pod_sandbox_id: id('a'),
            config: ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: name.into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                labels: [("k".to_owned(), "v".to_owned())].into(),
                ..Default::default()
            },
            state,
            in_flight,
            created_at_nanos: 1_700_000_000_000_000_001,
            started_at_nanos: 1_700_000_000_000_000_002,
            finished_at_nanos: 1_700_000_000_000_000_003,
            exit_code: Some(7),
            termination: None,
            stop_signal: Signal::Sigint as i32,
            resolved_log_path: Some(ContainerLogPath::new(LOG).unwrap()),
            applied_user: Some(AppliedUser::new(1000, 1000, vec![2000])),
            resolved_image: Some(
                ResolvedImage::new(
                    digest(),
                    Some(format!("busybox@sha256:{}", "ab".repeat(32))),
                )
                .with_tag(Some("busybox:1.36".into())),
            ),
        }
    }

    fn cok(d: &ContainerRecordData) -> ListedRecord {
        ListedRecord {
            id: RecordId::new(&d.id).unwrap(),
            outcome: Ok(d.encode().unwrap()),
        }
    }

    type Snap = (String, ContainerState, bool, bool);

    fn csnap(s: &CriRuntimeService) -> Vec<Snap> {
        let r = s.registry.lock().unwrap();
        let mut v: Vec<_> = r
            .containers
            .iter()
            .map(|(k, v)| (k.clone(), v.state, v.runtime_owned, v.in_flight))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    fn readopt_all(e: &Env) -> Result<super::ContainerReadoption, CriError> {
        e.svc.readopt_sandboxes(ListBudget::default()).unwrap();
        e.svc.readopt_containers(ListBudget::default())
    }

    fn state_calls(core: &FakeCore) -> Vec<String> {
        core.calls.lock().unwrap().clone()
    }

    /// CRI-1・OCI-7・CORE-1: 照合表の全 15 セル（in_flight 5 種 × core 3 種）を具体値で固定する。
    #[test]
    fn cri1_oci7_reconcile_table_all_cells() {
        use ContainerState::{Created, Exited, Running, Unknown};
        let present = CorePresence::Present(RuntimeLifecycle::Running);
        let reg = |state, runtime_owned, bucket| Outcome::Register {
            state,
            runtime_owned,
            bucket,
        };
        let cases = [
            // 確定（in_flight なし）
            (None, present, reg(Running, true, Bucket::Present)),
            (
                None,
                CorePresence::Absent,
                reg(Exited, false, Bucket::AbsentExited),
            ),
            (
                None,
                CorePresence::Undetermined,
                reg(Unknown, true, Bucket::Undetermined),
            ),
            // in_flight=create
            (
                Some(InFlightKind::Create),
                present,
                reg(Unknown, true, Bucket::Present),
            ),
            (
                Some(InFlightKind::Create),
                CorePresence::Absent,
                Outcome::StaleCreate,
            ),
            (
                Some(InFlightKind::Create),
                CorePresence::Undetermined,
                reg(Unknown, true, Bucket::Undetermined),
            ),
            // in_flight=start
            (
                Some(InFlightKind::Start),
                present,
                reg(Running, true, Bucket::Present),
            ),
            (
                Some(InFlightKind::Start),
                CorePresence::Absent,
                reg(Exited, false, Bucket::AbsentExited),
            ),
            (
                Some(InFlightKind::Start),
                CorePresence::Undetermined,
                reg(Unknown, true, Bucket::Undetermined),
            ),
            // in_flight=stop
            (
                Some(InFlightKind::Stop),
                present,
                reg(Running, true, Bucket::Present),
            ),
            (
                Some(InFlightKind::Stop),
                CorePresence::Absent,
                reg(Exited, false, Bucket::AbsentExited),
            ),
            (
                Some(InFlightKind::Stop),
                CorePresence::Undetermined,
                reg(Unknown, true, Bucket::Undetermined),
            ),
            // in_flight=remove
            (
                Some(InFlightKind::Remove),
                present,
                reg(Unknown, true, Bucket::Present),
            ),
            (
                Some(InFlightKind::Remove),
                CorePresence::Absent,
                reg(Unknown, true, Bucket::RemovePending),
            ),
            (
                Some(InFlightKind::Remove),
                CorePresence::Undetermined,
                reg(Unknown, true, Bucket::Undetermined),
            ),
        ];
        for (in_flight, probe, want) in cases {
            assert_eq!(
                reconcile(in_flight, probe),
                want,
                "{in_flight:?} x {probe:?}"
            );
        }
        // core の lifecycle の写像（確定 × Present）。
        assert_eq!(state_of_lifecycle(RuntimeLifecycle::Creating), Unknown);
        assert_eq!(state_of_lifecycle(RuntimeLifecycle::Created), Created);
        assert_eq!(state_of_lifecycle(RuntimeLifecycle::Running), Running);
        assert_eq!(state_of_lifecycle(RuntimeLifecycle::Stopped), Exited);
        assert_eq!(state_of_lifecycle(RuntimeLifecycle::Unknown), Unknown);
    }

    /// CRI-1・OCI-7: 公開経路での具体値（状態・runtime_owned・計上・保持量）と、core には `state` しか呼ばないこと。
    #[test]
    fn cri1_oci7_readopt_containers_values_and_counts() {
        let recs = [
            cdata('1', "c1", None, ContainerState::Running),
            cdata('2', "c2", None, ContainerState::Running),
            cdata('3', "c3", None, ContainerState::Running),
            cdata(
                '4',
                "c4",
                Some(InFlightKind::Create),
                ContainerState::Created,
            ),
            cdata(
                '5',
                "c5",
                Some(InFlightKind::Remove),
                ContainerState::Exited,
            ),
            cdata('6', "c6", None, ContainerState::Created),
            cdata('7', "c7", None, ContainerState::Created),
        ];
        let core = [
            (id('1'), Core::Running),
            (id('2'), Core::Stopped),
            // 3・4・5 は core に無い。
            (id('6'), Core::Fail(ErrorCode::Internal)),
            (id('7'), Core::Creating),
            // CRI 記録の無い core のコンテナ（触れない）。
            (id('e'), Core::Running),
        ];
        let e = env(recs.iter().map(cok).collect(), &core);
        let r = readopt_all(&e).unwrap();
        assert_eq!(
            (
                r.adopted,
                r.present,
                r.absent_exited,
                r.remove_pending,
                r.undetermined,
                r.stale_create,
                r.broken.total()
            ),
            (6, 3, 1, 1, 1, 1, 0)
        );
        assert_eq!(r.stale_create_ids(), &[id('4')]);
        assert_eq!(
            csnap(&e.svc),
            vec![
                (id('1'), ContainerState::Running, true, false),
                (id('2'), ContainerState::Exited, true, false),
                (id('3'), ContainerState::Exited, false, false),
                (id('5'), ContainerState::Unknown, true, false),
                (id('6'), ContainerState::Unknown, true, false),
                (id('7'), ContainerState::Unknown, true, false),
            ]
        );
        // 記録の値は保持される（終了コードは記録の値。core の 9 では上書きしない）。
        {
            let reg = e.svc.registry.lock().unwrap();
            let c2 = reg.containers.get(&id('2')).unwrap();
            assert_eq!(c2.exit_code, Some(7));
            assert_eq!(c2.started_at_nanos, 1_700_000_000_000_000_002);
            assert_eq!(c2.finished_at_nanos, 1_700_000_000_000_000_003);
            assert_eq!(c2.stop_signal, Signal::Sigint as i32);
            assert_eq!(c2.resolved_log_path.as_ref().map(|p| p.as_str()), Some(LOG));
            assert_eq!(c2.applied_user.as_ref().map(|u| u.uid()), Some(1000));
            assert_eq!(
                c2.resolved_image.as_ref().and_then(|i| i.tag()),
                Some("busybox:1.36")
            );
            assert_eq!(reg.container_keys.len(), 6);
            // 保持量: 数え直した config 分 + ログパス + 識別情報 + イメージ。
            let d = &recs[1];
            let base = ContainerRecordData::decode(&d.encode().unwrap(), &d.id)
                .unwrap()
                .retained_bytes;
            let image = d.resolved_image.as_ref().unwrap();
            let extra = LOG.len()
                + (4 + 64)
                + (image.image_ref().len() + image.id_str().len() + "busybox:1.36".len() + 64);
            assert_eq!(c2.retained_bytes, base + extra);
            let sum: usize = reg.containers.values().map(|c| c.retained_bytes).sum();
            assert_eq!(reg.container_retained_bytes, sum);
        }
        // 副作用なし: ストアへ書かず消さず、core には記録の 7 件の `state` だけ。
        assert_eq!(*e.store.calls.lock().unwrap(), (0, 0));
        assert_eq!(*e.bundles.0.lock().unwrap(), 0);
        let mut calls = state_calls(&e.core);
        calls.sort();
        let want: Vec<String> = "1234567"
            .chars()
            .map(|c| format!("state:{}", id(c)))
            .collect();
        assert_eq!(calls, want);
        let codes = load_codes(&e.rec);
        // sandbox 1 件 + コンテナ 7 件（stale_create を含む）はすべて成功。
        assert_eq!(codes, vec![Code::Ok; 8]);
    }

    /// CRI-1・REPAIR-5: 確定できない応答（各種エラー・ID 不一致・期限切れ）は unknown で保持し、何も消さない。
    #[test]
    fn cri1_undetermined_keeps_record_and_deletes_nothing() {
        let cases = [
            Core::Fail(ErrorCode::Internal),
            Core::Fail(ErrorCode::Timeout),
            Core::Fail(ErrorCode::Unavailable),
            Core::Fail(ErrorCode::PermissionDenied),
            Core::Fail(ErrorCode::Unimplemented),
            Core::WrongId,
            Core::Sleep(Duration::from_millis(300)),
        ];
        for (i, case) in cases.into_iter().enumerate() {
            let c = char::from(b'1' + i as u8);
            let e = env(
                vec![cok(&cdata(c, "c", None, ContainerState::Running))],
                &[(id(c), case)],
            );
            let budget = ListBudget {
                per_record: Duration::from_millis(100),
                total: Duration::from_secs(5),
            };
            e.svc.readopt_sandboxes(budget).unwrap();
            let r = e.svc.readopt_containers(budget).unwrap();
            assert_eq!((r.adopted, r.undetermined), (1, 1), "case {i}");
            assert_eq!(
                csnap(&e.svc),
                vec![(id(c), ContainerState::Unknown, true, false)],
                "case {i}"
            );
            assert_eq!(*e.store.calls.lock().unwrap(), (0, 0));
            assert_eq!(state_calls(&e.core), vec![format!("state:{}", id(c))]);
            // CONTAINER_UNKNOWN で公開される。
            let st = e.svc.registry.lock().unwrap().containers[&id(c)].to_status(&id(c));
            assert_eq!(st.state, v1_unknown());
        }
    }

    fn v1_unknown() -> i32 {
        crate::runtime::v1::ContainerState::ContainerUnknown as i32
    }

    /// CRI-1: 実行層が未注入なら照会できず、全件 unknown で保持する。記録 0 件なら何もしない。
    #[test]
    fn cri1_readopt_containers_without_runtime_holds_unknown() {
        let e = env_with(
            vec![ok(&data('a', "p"))],
            vec![cok(&cdata('1', "c", None, ContainerState::Running))],
            &[],
            false,
            |s| s,
        );
        let r = readopt_all(&e).unwrap();
        assert_eq!((r.adopted, r.undetermined), (1, 1));
        assert_eq!(
            csnap(&e.svc),
            vec![(id('1'), ContainerState::Unknown, true, false)]
        );

        let e = env_with(vec![ok(&data('a', "p"))], vec![], &[], false, |s| s);
        let r = readopt_all(&e).unwrap();
        assert_eq!(r, super::ContainerReadoption::default());
    }

    /// CRI-1: 所属 sandbox の無い記録は壊れた記録として数え、登録も照会も削除もしない。
    #[test]
    fn cri1_parentless_record_is_broken_not_registered() {
        let mut orphan = cdata('2', "c2", None, ContainerState::Running);
        orphan.pod_sandbox_id = id('9');
        let e = env(
            vec![
                cok(&cdata('1', "c1", None, ContainerState::Running)),
                cok(&orphan),
            ],
            &[(id('1'), Core::Running), (id('2'), Core::Running)],
        );
        let r = readopt_all(&e).unwrap();
        assert_eq!(
            (r.adopted, r.broken.parentless, r.broken.total()),
            (1, 1, 1)
        );
        assert_eq!(csnap(&e.svc).len(), 1);
        assert_eq!(*e.store.calls.lock().unwrap(), (0, 0));
        assert_eq!(state_calls(&e.core), vec![format!("state:{}", id('1'))]);
        assert_eq!(load_codes(&e.rec), vec![Code::Ok, Code::Ok, Code::DataLoss]);
    }

    /// CRI-1: 同じ (sandbox, name, attempt) は ID の小さい方だけ登録する（stale_create を除いた後で判定する）。
    #[test]
    fn cri1_duplicate_key_keeps_smaller_id() {
        let e = env(
            vec![
                cok(&cdata(
                    '1',
                    "same",
                    Some(InFlightKind::Create),
                    ContainerState::Created,
                )),
                cok(&cdata('2', "same", None, ContainerState::Running)),
                cok(&cdata('3', "same", None, ContainerState::Running)),
            ],
            &[(id('2'), Core::Running), (id('3'), Core::Running)],
        );
        let r = readopt_all(&e).unwrap();
        // '1' は core に無い create なので登録せず、'2' が鍵を取り、'3' が重複になる。
        assert_eq!(
            (r.adopted, r.stale_create, r.broken.duplicate_metadata),
            (1, 1, 1)
        );
        assert_eq!(csnap(&e.svc)[0].0, id('2'));
    }

    /// CRI-1: コンテナの registry が空でなければ拒否し、記録ストア未注入は何もしない。
    #[test]
    fn cri1_readopt_containers_requires_empty_registry_and_store() {
        let e = env(
            vec![cok(&cdata('1', "c", None, ContainerState::Running))],
            &[(id('1'), Core::Running)],
        );
        readopt_all(&e).unwrap();
        let err = e.svc.readopt_containers(ListBudget::default()).unwrap_err();
        assert_eq!(err.code().grpc_code(), Code::FailedPrecondition);

        let s = CriRuntimeService::new();
        assert_eq!(
            s.readopt_containers(ListBudget::default()).unwrap(),
            super::ContainerReadoption::default()
        );
    }

    /// REPAIR-5: 件数・保持量の上限超過は起動失敗で、registry は空のまま。
    #[test]
    fn repair5_container_readopt_over_limits_fails_closed() {
        let recs = vec![
            cok(&cdata('1', "c1", None, ContainerState::Running)),
            cok(&cdata('2', "c2", None, ContainerState::Running)),
        ];
        let core = [(id('1'), Core::Running), (id('2'), Core::Running)];
        for limits in [
            super::super::ContainerLimits::new().with_max_containers(1),
            super::super::ContainerLimits::new().with_max_retained_bytes(1),
        ] {
            let e = env_with(vec![ok(&data('a', "p"))], recs.clone(), &core, true, |s| {
                s.with_container_limits(limits)
            });
            e.svc.readopt_sandboxes(ListBudget::default()).unwrap();
            let err = e.svc.readopt_containers(ListBudget::default()).unwrap_err();
            assert_eq!(err.code().grpc_code(), Code::FailedPrecondition);
            let reg = e.svc.registry.lock().unwrap();
            assert!(reg.containers.is_empty() && reg.container_keys.is_empty());
            assert_eq!(reg.container_retained_bytes, 0);
        }
    }

    /// REPAIR-5: 照会の途中で全体の期限が切れたら DEADLINE_EXCEEDED で失敗し、registry は空のまま。
    #[test]
    fn repair5_container_readopt_total_deadline_fails_closed() {
        let e = env(
            vec![
                cok(&cdata('1', "c1", None, ContainerState::Running)),
                cok(&cdata('2', "c2", None, ContainerState::Running)),
            ],
            &[
                (id('1'), Core::Sleep(Duration::from_millis(400))),
                (id('2'), Core::Running),
            ],
        );
        e.svc.readopt_sandboxes(ListBudget::default()).unwrap();
        let budget = ListBudget {
            per_record: Duration::from_secs(1),
            total: Duration::from_millis(50),
        };
        let err = e.svc.readopt_containers(budget).unwrap_err();
        assert_eq!(err.code().grpc_code(), Code::DeadlineExceeded);
        assert!(csnap(&e.svc).is_empty());
        assert_eq!(*e.store.calls.lock().unwrap(), (0, 0));
    }

    /// REPAIR-5: 壊れた記録だけの経路でも全体期限を検査し、期限切れなら registry を変えず失敗する。
    #[test]
    fn repair5_container_readopt_deadline_checked_on_broken_path() {
        let broken = ListedRecord {
            id: RecordId::new(&id('9')).unwrap(),
            outcome: Ok(b"junk".to_vec()),
        };
        let e = env(
            vec![
                cok(&cdata('1', "c1", None, ContainerState::Running)),
                broken,
            ],
            &[(id('1'), Core::Running)],
        );
        e.svc.readopt_sandboxes(ListBudget::default()).unwrap();
        let budget = ListBudget {
            per_record: Duration::from_secs(1),
            total: Duration::ZERO,
        };
        let err = e.svc.readopt_containers(budget).unwrap_err();
        assert_eq!(err.code().grpc_code(), Code::DeadlineExceeded);
        assert!(csnap(&e.svc).is_empty());
    }

    /// REPAIR-5: 保持量の積算が上限を超えた時点で拒否する（2 件目で超過）。
    #[test]
    fn repair5_container_readopt_cumulative_bytes_rejected_incrementally() {
        let recs = vec![
            cok(&cdata('1', "c1", None, ContainerState::Running)),
            cok(&cdata('2', "c2", None, ContainerState::Running)),
        ];
        let core = [(id('1'), Core::Running), (id('2'), Core::Running)];
        let one = {
            let e = env(recs[..1].to_vec(), &core);
            readopt_all(&e).unwrap();
            e.svc.registry.lock().unwrap().container_retained_bytes
        };
        let e = env_with(vec![ok(&data('a', "p"))], recs, &core, true, |s| {
            s.with_container_limits(
                super::super::ContainerLimits::new().with_max_retained_bytes(one + 1),
            )
        });
        e.svc.readopt_sandboxes(ListBudget::default()).unwrap();
        let err = e.svc.readopt_containers(ListBudget::default()).unwrap_err();
        assert_eq!(err.code().grpc_code(), Code::FailedPrecondition);
        assert!(csnap(&e.svc).is_empty());
    }

    /// REPAIR-4: 要約行は固定語彙で、ID を含まない。
    #[test]
    fn repair4_container_summary_line_is_fixed_vocabulary() {
        let e = env(
            vec![
                cok(&cdata('1', "c1", None, ContainerState::Running)),
                cok(&cdata(
                    '4',
                    "c4",
                    Some(InFlightKind::Create),
                    ContainerState::Created,
                )),
            ],
            &[(id('1'), Core::Running)],
        );
        let r = readopt_all(&e).unwrap();
        let line = r.summary_line();
        assert_eq!(
            line,
            "cri record readoption: kind=container adopted=1 present=1 absent_exited=0 remove_pending=0 undetermined=0 stale_create=1 broken=0 malformed=0 not_regular_file=0 too_long=0 unreadable=0 unrecognized=0 duplicate_metadata=0 parentless=0"
        );
        assert!(!line.contains(&id('1')) && !line.contains(&id('4')));
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// CRI-2: 確定 × core に無い（runtime_owned=false）の Remove は core の delete を呼ばず、メモリ上の除去だけ。
    #[test]
    fn cri2_readopted_absent_confirmed_remove_never_calls_core_delete() {
        let e = env(
            vec![cok(&cdata('3', "c", None, ContainerState::Running))],
            &[],
        );
        readopt_all(&e).unwrap();
        rt().block_on(RuntimeService::remove_container(
            &e.svc,
            tonic::Request::new(RemoveContainerRequest {
                container_id: id('3'),
            }),
        ))
        .unwrap();
        assert!(csnap(&e.svc).is_empty());
        assert!(
            !state_calls(&e.core)
                .iter()
                .any(|c| c.starts_with("delete:"))
        );
        // R8: bundle の解放 1 回と記録ファイルの削除 1 回（core の資源が無いので delete は呼ばない）。
        assert_eq!(*e.bundles.0.lock().unwrap(), 1);
        assert_eq!(*e.bundles.2.lock().unwrap(), vec![id('3')]);
        assert_eq!(*e.store.removed.lock().unwrap(), vec![id('3')]);
        assert_eq!(e.svc.registry.lock().unwrap().container_retained_bytes, 0);
    }

    /// OCI-7・CRI-1（R8 #2937）: 再採用した `runtime_owned=false` の Remove で bundle の解放に失敗したら、
    /// 記録ファイルは消さず exited・`in_flight=false` で保持し、再試行で完了する。
    #[test]
    fn cri2_readopted_absent_remove_release_failure_keeps_exited() {
        let e = env(
            vec![cok(&cdata('3', "c", None, ContainerState::Running))],
            &[],
        );
        readopt_all(&e).unwrap();
        *e.bundles.1.lock().unwrap() = true;
        let req = || {
            tonic::Request::new(RemoveContainerRequest {
                container_id: id('3'),
            })
        };
        let err = rt()
            .block_on(RuntimeService::remove_container(&e.svc, req()))
            .unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(
            csnap(&e.svc),
            vec![(id('3'), ContainerState::Exited, false, false)]
        );
        assert!(e.store.removed.lock().unwrap().is_empty());
        assert!(
            !state_calls(&e.core)
                .iter()
                .any(|c| c.starts_with("delete:"))
        );
        *e.bundles.1.lock().unwrap() = false;
        rt().block_on(RuntimeService::remove_container(&e.svc, req()))
            .unwrap();
        assert!(csnap(&e.svc).is_empty());
        assert_eq!(*e.store.removed.lock().unwrap(), vec![id('3')]);
    }

    /// OCI-7・CRI-1（R8 #2937）: 記録ファイルの削除に失敗したら exited で保持し、再試行で完了する。
    #[test]
    fn cri2_readopted_absent_remove_record_failure_keeps_exited() {
        let e = env(
            vec![cok(&cdata('3', "c", None, ContainerState::Running))],
            &[],
        );
        readopt_all(&e).unwrap();
        *e.store.fail_remove.lock().unwrap() = true;
        let req = || {
            tonic::Request::new(RemoveContainerRequest {
                container_id: id('3'),
            })
        };
        assert!(
            rt().block_on(RuntimeService::remove_container(&e.svc, req()))
                .is_err()
        );
        assert_eq!(
            csnap(&e.svc),
            vec![(id('3'), ContainerState::Exited, false, false)]
        );
        *e.store.fail_remove.lock().unwrap() = false;
        rt().block_on(RuntimeService::remove_container(&e.svc, req()))
            .unwrap();
        assert!(csnap(&e.svc).is_empty());
    }

    /// OCI-7・CRI-1（R8 #2937）: RemovePodSandbox は配下の `runtime_owned=false` の子も bundle と記録を回収し、
    /// core の delete は `runtime_owned` の子の 1 回だけ。子の解放に失敗したら sandbox も残る。
    #[test]
    fn cri2_readopted_absent_remove_pod_sandbox_releases_children() {
        use crate::runtime::v1::RemovePodSandboxRequest;
        let e = env(
            vec![
                cok(&cdata('3', "c3", None, ContainerState::Running)),
                cok(&cdata('4', "c4", None, ContainerState::Running)),
            ],
            &[(id('4'), Core::Running)],
        );
        readopt_all(&e).unwrap();
        *e.bundles.1.lock().unwrap() = true;
        let req = || {
            tonic::Request::new(RemovePodSandboxRequest {
                pod_sandbox_id: id('a'),
            })
        };
        assert!(
            rt().block_on(RuntimeService::remove_pod_sandbox(&e.svc, req()))
                .is_err()
        );
        assert!(!e.svc.registry.lock().unwrap().records.is_empty());
        *e.bundles.1.lock().unwrap() = false;
        rt().block_on(RuntimeService::remove_pod_sandbox(&e.svc, req()))
            .unwrap();
        assert!(csnap(&e.svc).is_empty());
        assert!(e.svc.registry.lock().unwrap().records.is_empty());
        let deletes: std::collections::BTreeSet<String> = state_calls(&e.core)
            .into_iter()
            .filter(|c| c.starts_with("delete:"))
            .collect();
        // runtime_owned の子（'4'）だけが core の delete の対象（'3' は呼ばない）。
        assert_eq!(
            deletes,
            std::collections::BTreeSet::from([format!("delete:{}", id('4'))])
        );
        let released = e.bundles.2.lock().unwrap().clone();
        assert!(released.contains(&id('3')) && released.contains(&id('4')));
        let removed = e.store.removed.lock().unwrap().clone();
        assert!(removed.contains(&id('3')) && removed.contains(&id('4')));
    }

    // ---- stale_create の解放（R8 #2937。OCI-7・CRI-1・REPAIR-5） ----

    fn stale_env(core: &[(String, Core)]) -> (Env, super::ContainerReadoption) {
        let e = env(
            vec![
                cok(&cdata(
                    '4',
                    "c4",
                    Some(InFlightKind::Create),
                    ContainerState::Created,
                )),
                cok(&cdata(
                    '5',
                    "c5",
                    Some(InFlightKind::Create),
                    ContainerState::Created,
                )),
            ],
            core,
        );
        let r = readopt_all(&e).unwrap();
        assert_eq!(r.stale_create_ids(), &[id('4'), id('5')]);
        (e, r)
    }

    /// OCI-7: stale_create は再照会が NOT_FOUND のとき、bundle の解放 → 記録の削除の順で進む。registry は変えない。
    #[test]
    fn oci7_stale_create_released_then_record_removed() {
        let (e, r) = stale_env(&[]);
        let out = e
            .svc
            .release_stale_creates(&r, ListBudget::default())
            .unwrap();
        assert_eq!((out.released, out.kept, out.release_failed), (2, 0, 0));
        assert_eq!(*e.bundles.2.lock().unwrap(), vec![id('4'), id('5')]);
        assert_eq!(*e.store.removed.lock().unwrap(), vec![id('4'), id('5')]);
        assert!(csnap(&e.svc).is_empty());
    }

    /// OCI-7: 解放に失敗したら記録は消さない。
    #[test]
    fn oci7_stale_create_release_failure_keeps_record() {
        let (e, r) = stale_env(&[]);
        *e.bundles.1.lock().unwrap() = true;
        let out = e
            .svc
            .release_stale_creates(&r, ListBudget::default())
            .unwrap();
        assert_eq!((out.released, out.release_failed), (0, 2));
        assert!(e.store.removed.lock().unwrap().is_empty());
    }

    /// OCI-7: 解放は済んだが記録の削除に失敗した件は record_remove_failed。
    #[test]
    fn oci7_stale_create_record_remove_failure_is_counted() {
        let (e, r) = stale_env(&[]);
        *e.store.fail_remove.lock().unwrap() = true;
        let out = e
            .svc
            .release_stale_creates(&r, ListBudget::default())
            .unwrap();
        assert_eq!((out.released, out.record_remove_failed), (0, 2));
        assert_eq!(*e.bundles.0.lock().unwrap(), 2);
    }

    /// OCI-7: 再照会が Present・結果不明なら何もしない。
    #[test]
    fn oci7_stale_create_not_absent_on_reprobe_is_kept() {
        let (e, r) = stale_env(&[]);
        // 再採用の時点では NOT_FOUND だったが、再照会の時点で現れた・不明になった場合を作る。
        e.core.states.lock().unwrap().insert(id('4'), Core::Running);
        e.core
            .states
            .lock()
            .unwrap()
            .insert(id('5'), Core::Fail(ErrorCode::Internal));
        let out = e
            .svc
            .release_stale_creates(&r, ListBudget::default())
            .unwrap();
        assert_eq!((out.released, out.kept), (0, 2));
        assert_eq!(*e.bundles.0.lock().unwrap(), 0);
        assert!(e.store.removed.lock().unwrap().is_empty());
    }

    /// REPAIR-5: 全体の期限が尽きていたら試みない。
    #[test]
    fn repair5_stale_create_total_deadline_stops() {
        let (e, r) = stale_env(&[]);
        let budget = ListBudget {
            per_record: Duration::from_secs(1),
            total: Duration::ZERO,
        };
        let out = e.svc.release_stale_creates(&r, budget).unwrap();
        assert_eq!((out.not_attempted, out.released), (2, 0));
        assert_eq!(*e.bundles.0.lock().unwrap(), 0);
    }

    /// 既定の結果（空）では何もしない。
    #[test]
    fn oci7_stale_create_default_readoption_is_noop() {
        let e = env(vec![], &[]);
        let out = e
            .svc
            .release_stale_creates(
                &super::ContainerReadoption::default(),
                ListBudget::default(),
            )
            .unwrap();
        assert_eq!(out, super::StaleCreateRelease::default());
    }

    /// REPAIR-4: 要約行は固定語彙（文字列全体）。
    #[test]
    fn repair4_stale_create_summary_line_is_fixed_vocabulary() {
        let s = super::StaleCreateRelease {
            released: 1,
            kept: 2,
            release_failed: 3,
            record_remove_failed: 4,
            not_attempted: 5,
            skipped: 6,
        };
        assert_eq!(
            s.summary_line(),
            "cri stale create release: released=1 kept=2 release_failed=3 record_remove_failed=4 not_attempted=5 skipped=6"
        );
    }

    /// CRI-2: in_flight=remove × core に無い は Remove の続きを完了できる（delete の NOT_FOUND を許容し、
    /// bundle の解放 → 記録の削除まで進む）。
    #[test]
    fn cri2_readopted_remove_pending_absent_completes_remove() {
        let e = env(
            vec![cok(&cdata(
                '5',
                "c",
                Some(InFlightKind::Remove),
                ContainerState::Exited,
            ))],
            &[],
        );
        let r = readopt_all(&e).unwrap();
        assert_eq!(r.remove_pending, 1);
        rt().block_on(RuntimeService::remove_container(
            &e.svc,
            tonic::Request::new(RemoveContainerRequest {
                container_id: id('5'),
            }),
        ))
        .unwrap();
        assert!(csnap(&e.svc).is_empty());
        let deletes = state_calls(&e.core)
            .into_iter()
            .filter(|c| c.starts_with("delete:"))
            .count();
        assert_eq!(deletes, 1);
        assert_eq!(*e.bundles.0.lock().unwrap(), 1);
        // 記録の削除（RecordStore::remove）が 1 回。
        assert_eq!(*e.store.calls.lock().unwrap(), (0, 1));
    }

    /// CRI-2: in_flight=create × core にある は unknown で、Remove は core の delete を 1 回呼ぶ。
    #[test]
    fn cri2_readopted_in_flight_create_present_remove_calls_core_delete_once() {
        let e = env(
            vec![cok(&cdata(
                '4',
                "c",
                Some(InFlightKind::Create),
                ContainerState::Created,
            ))],
            &[(id('4'), Core::Created)],
        );
        readopt_all(&e).unwrap();
        rt().block_on(RuntimeService::remove_container(
            &e.svc,
            tonic::Request::new(RemoveContainerRequest {
                container_id: id('4'),
            }),
        ))
        .unwrap();
        let deletes = state_calls(&e.core)
            .into_iter()
            .filter(|c| c.starts_with("delete:"))
            .count();
        assert_eq!(deletes, 1);
        assert!(csnap(&e.svc).is_empty());
    }

    /// CRI-2: 再採用した sandbox は NotReady なので、配下の Created でも Start は拒否される。
    #[test]
    fn cri2_readopted_container_start_is_rejected() {
        let e = env(
            vec![cok(&cdata('1', "c", None, ContainerState::Created))],
            &[(id('1'), Core::Created)],
        );
        readopt_all(&e).unwrap();
        let err = rt()
            .block_on(RuntimeService::start_container(
                &e.svc,
                tonic::Request::new(StartContainerRequest {
                    container_id: id('1'),
                }),
            ))
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(!state_calls(&e.core).iter().any(|c| c.starts_with("start:")));
    }
}
