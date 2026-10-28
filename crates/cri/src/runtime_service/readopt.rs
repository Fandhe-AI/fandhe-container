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
//! 未実装（REPAIR-3）: コンテナ記録の再採用と core の状態との照合は R7 #2936、保持役の素性による pending の解決は
//! R11 #2940、`pod_netns`・provider 識別子の永続と再起動後の `tear_down` は R12 #2941、本番の配線は R9 #2938。

use std::time::Instant;

use tonic::Code;

use super::record::SandboxRecordData;
use super::{
    CriRuntimeService, ListBudget, ListLimits, ListedRecord, RecordKind, RecordReadFailure,
    SandboxRecord, SandboxState,
};
use crate::error::CriError;
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
}
