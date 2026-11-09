//! 実機前提試験（`cri_exec_real.rs`・`cri_attach_real.rs`）が失敗の後に残す sandbox・コンテナの記録を回収する共有部品
//! （CRI-1・CRI-6・REPAIR-4・REPAIR-5・REPAIR-12・#4142）。
//!
//! 背景: 2 試験は本物の既定の状態ルートを共有する。後始末が成功経路の末尾にしか無いと、途中の panic や watchdog で
//! sandbox とコンテナの記録が残り、次の実行の `RunPodSandbox` が同じ metadata で `ALREADY_EXISTS` になる。
//!
//! 契約（2 層）:
//! - 第 1 層: 試験は実行ごとの一意なトークン（[`run_token`]）をラベルと sandbox の uid に入れ、作った ID を台帳
//!   （[`Ledger`]）へ登録する。失敗した試行の後に [`reclaim`] が、台帳の ID と自分のトークンのラベルで絞った一覧の和
//!   だけを Stop / Remove する。フィルタなしの一覧からは消さず、記録ファイルにも触れない（他人の記録を消さない）
//! - 第 2 層: 回収にも失敗して記録が残っても、次の実行は uid が違うので `ALREADY_EXISTS` にならない。残った ID と
//!   `docs/setup/cri-record-recovery.md` への誘導を 1 行で出す（[`left_line`]）
//!
//! 呼び出し元: 取り込み側の試験が `#[path]` で共有する。`Drop` では `.await` できないため RPC を呼ぶガードは作らず、
//! 本体を [`guarded`]（`tokio::spawn` で panic を捕まえ、期限切れは abort）で走らせた後に試験自身が [`reclaim`] を呼ぶ。
//!
//! 所有者 label（#4285）: 実行ごとのトークンでは過去の実行の残骸を回収できない。そこで試験名を値にした安定な 2 つ目の
//! label（[`OWNER_KEY`]）を足す。値は許可リスト [`OWNERS`] に固定し、先頭の回収（[`reclaim_by_selector`] を許可リストの値ごとに
//! 呼ぶ）はこの label を持つ記録だけを消す。CRI の `label_selector` は完全一致のため、許可リストの値ごとに一覧を取る。
//! label の無い記録・許可リスト外の値の記録には触れない（手動回収。`docs/setup/cri-record-recovery.md`）。
//!
//! plugin 自体が死んだ場合（#4285）: 本部品は接続済みの client だけを使う。接続できないとき [`reclaim`] は `unverified` を
//! 返すので、呼び出し側が [`plugin_unreachable`] で判定し、同じ状態ルートで plugin を起動し直してから回収し直す
//! （`container_grpc.rs`・`cri_exec_real.rs` の段 4）。`cri_attach_real.rs` の外側の回収で起動し直す経路は未対応（REPAIR-3）。
//!
//! 取り込みの注意: `#[path]` で複数の試験バイナリへ取り込まれるため、本部品の自己照合の `#[test]` は取り込み側ごとに重ねて走る。

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_cri::runtime::v1 as cri;
use fandhe_container_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use fandhe_container_plugin::PluginErrorCode;
use fandhe_container_plugin::grpc::call_with_deadline;
use tonic::transport::Channel;

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 試験が作った記録に付けるラベルのキー。値は [`run_token`]。
pub const LABEL_KEY: &str = "io.fandhe-container.test.run";
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 安定した所有者 label のキー（#4285）。値は [`OWNERS`] のいずれか。
pub const OWNER_KEY: &str = "io.fandhe-container.test.owner";
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 所有者 label の許可リスト（試験名。先頭の回収の対象はこの値の記録だけ）。
pub const OWNERS: [&str; 4] = [
    "production_binary_full_lifecycle_real",
    "production_binary_restart_readopts_running_container_real",
    "production_binary_exec_real",
    "production_binary_attach_real",
];
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 回収全体の上限（REPAIR-5）。
pub const CLEANUP_BUDGET: Duration = Duration::from_secs(60);
/// 回収の RPC 1 回の上限。
const RPC_LIMIT: Duration = Duration::from_secs(20);
/// 本体の期限から差し引く余裕。
const MARGIN: Duration = Duration::from_secs(5);
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 注入した失敗の 1 回目の試行の上限（2 回目の時間を食いつぶさない）。
pub const INJECT_ATTEMPT_LIMIT: Duration = Duration::from_secs(120);

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 実行ごとに一意なトークン（pid と UNIX 時刻 ns。文字種は `[0-9a-z-]`）。
pub fn run_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// sandbox の uid（`<prefix>-<token>`）。
pub fn sandbox_uid(prefix: &str, token: &str) -> String {
    format!("{prefix}-{token}")
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// sandbox・コンテナに付けるラベル。
pub fn labels(token: &str) -> HashMap<String, String> {
    HashMap::from([(LABEL_KEY.to_owned(), token.to_owned())])
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 所有者 label だけの selector（先頭の回収用）。
pub fn owner_selector(owner: &str) -> HashMap<String, String> {
    HashMap::from([(OWNER_KEY.to_owned(), owner.to_owned())])
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// `PodSandboxConfig`・`ContainerConfig` の `labels` 用（`BTreeMap`）。トークンと所有者の 2 つを持つ。
/// `owner` が許可リストに無いのは試験コードの誤りなので panic する。
pub fn config_labels(owner: &str, token: &str) -> std::collections::BTreeMap<String, String> {
    assert!(OWNERS.contains(&owner), "owner {owner:?} is not in OWNERS");
    let mut m: std::collections::BTreeMap<String, String> = labels(token).into_iter().collect();
    m.insert(OWNER_KEY.to_owned(), owner.to_owned());
    m
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 試験が作った ID の台帳。
#[derive(Default, Debug)]
pub struct OwnedIds {
    sandboxes: Vec<String>,
    containers: Vec<String>,
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub type Ledger = Arc<Mutex<OwnedIds>>;

fn lock(l: &Ledger) -> std::sync::MutexGuard<'_, OwnedIds> {
    l.lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn record_sandbox(l: &Ledger, id: &str) {
    lock(l).sandboxes.push(id.to_owned());
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn record_container(l: &Ledger, id: &str) {
    lock(l).containers.push(id.to_owned());
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn forget_sandbox(l: &Ledger, id: &str) {
    lock(l).sandboxes.retain(|s| s != id);
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn forget_container(l: &Ledger, id: &str) {
    lock(l).containers.retain(|s| s != id);
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 試行の失敗の種類。
pub enum AttemptFailure {
    Panicked(Box<dyn Any + Send>),
    Deadline,
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 本体を `tokio::spawn` で走らせ、panic は捕まえ、期限切れは abort して待ち切る。
pub async fn guarded<F>(fut: F, limit: Duration) -> Result<(), AttemptFailure>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut handle = tokio::spawn(fut);
    match tokio::time::timeout(limit, &mut handle).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) if e.is_panic() => Err(AttemptFailure::Panicked(e.into_panic())),
        Ok(Err(_)) => Err(AttemptFailure::Deadline),
        Err(_) => {
            handle.abort();
            let _ = handle.await;
            Err(AttemptFailure::Deadline)
        }
    }
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 注入する失敗の固定文言。
pub fn injected_message(test: &str) -> String {
    format!("{test}: injected failure after StartContainer (expected; reclaim self-check #4142)")
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// panic の payload が注入した失敗の文言そのものか（`&str`・`String` の両方を見る）。
pub fn is_injected(test: &str, payload: &(dyn Any + Send)) -> bool {
    let want = injected_message(test);
    let got = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied());
    got == Some(want.as_str())
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 本体に割ける期限。`watchdog` から経過・回収の予約（`cleanups` 回分）・余裕を引く（足りなければ 0）。
pub fn scenario_budget(elapsed: Duration, watchdog: Duration, cleanups: u32) -> Duration {
    watchdog
        .saturating_sub(elapsed)
        .saturating_sub(CLEANUP_BUDGET * cleanups)
        .saturating_sub(MARGIN)
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 回収の結果。
#[derive(Debug, Default, PartialEq)]
pub struct ReclaimReport {
    pub reclaimed_containers: Vec<String>,
    pub reclaimed_sandboxes: Vec<String>,
    pub left_containers: Vec<String>,
    pub left_sandboxes: Vec<String>,
    /// 最後の一覧取得が失敗し、残存の有無を確認できなかった理由（`list_containers: <code>` 等）。
    pub unverified: Vec<String>,
    /// 回収対象のトークン（未確認の報告に載せる）。
    pub token: String,
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
impl ReclaimReport {
    #[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
    pub fn is_clean(&self) -> bool {
        self.left_containers.is_empty()
            && self.left_sandboxes.is_empty()
            && self.unverified.is_empty()
    }
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 残骸があるときの固定の 1 行（REPAIR-4）。ID は 64 文字の 16 進で秘密ではない。無ければ `None`。
pub fn left_line(test: &str, r: &ReclaimReport) -> Option<String> {
    if r.is_clean() {
        return None;
    }
    if !r.unverified.is_empty() {
        return Some(format!(
            "{test}: cleanup could not verify cri records token={} reasons={} sandboxes={} containers={}; see docs/setup/cri-record-recovery.md",
            r.token,
            r.unverified.join(","),
            r.left_sandboxes.join(","),
            r.left_containers.join(",")
        ));
    }
    Some(format!(
        "{test}: cleanup left cri records sandboxes={} containers={}; see docs/setup/cri-record-recovery.md",
        r.left_sandboxes.join(","),
        r.left_containers.join(",")
    ))
}

fn limit(end: Instant) -> Duration {
    end.saturating_duration_since(Instant::now()).min(RPC_LIMIT)
}

fn push_unique(v: &mut Vec<String>, id: String) {
    if !v.contains(&id) {
        v.push(id);
    }
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 起動し直しが要るか（#4285）。一覧を確認できず（`unverified`）、何も回収できなかったとき真。
pub fn plugin_unreachable(r: &ReclaimReport) -> bool {
    !r.unverified.is_empty()
        && r.reclaimed_containers.is_empty()
        && r.reclaimed_sandboxes.is_empty()
}

/// label の selector で絞った一覧。失敗した一覧は空にして理由を 3 つ目に返す（残存なしとは見なさない）。
async fn list_by_selector(
    c: &mut RuntimeServiceClient<Channel>,
    selector: &HashMap<String, String>,
    end: Instant,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut errors = Vec::new();
    let selector = selector.clone();
    let containers = call_with_deadline(
        c.list_containers(cri::ListContainersRequest {
            filter: Some(cri::ContainerFilter {
                label_selector: selector.clone(),
                ..Default::default()
            }),
        }),
        limit(end),
    )
    .await
    .map(|r| {
        r.into_inner()
            .containers
            .into_iter()
            .map(|x| x.id)
            .collect()
    })
    .unwrap_or_else(|e| {
        errors.push(format!("list_containers: {}", e.code().as_str()));
        Vec::new()
    });
    let sandboxes = call_with_deadline(
        c.list_pod_sandbox(cri::ListPodSandboxRequest {
            filter: Some(cri::PodSandboxFilter {
                label_selector: selector,
                ..Default::default()
            }),
        }),
        limit(end),
    )
    .await
    .map(|r| r.into_inner().items.into_iter().map(|x| x.id).collect())
    .unwrap_or_else(|e| {
        errors.push(format!("list_pod_sandbox: {}", e.code().as_str()));
        Vec::new()
    });
    (containers, sandboxes, errors)
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// 台帳の ID と自分のトークンのラベルで絞った一覧の和だけを、期限つきで Stop / Remove する（R2・REPAIR-5）。
/// `NOT_FOUND` は回収済みとして扱う。
pub async fn reclaim(
    c: &mut RuntimeServiceClient<Channel>,
    ledger: &Ledger,
    token: &str,
    budget: Duration,
) -> ReclaimReport {
    reclaim_by_selector(c, ledger, labels(token), token, budget).await
}

#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
/// [`reclaim`] の一般形。`selector` は label の完全一致（トークン、または [`owner_selector`]）。`name` は未確認の報告に載せる
/// 識別子（トークン、または `owner=<値>`）。
pub async fn reclaim_by_selector(
    c: &mut RuntimeServiceClient<Channel>,
    ledger: &Ledger,
    selector: HashMap<String, String>,
    name: &str,
    budget: Duration,
) -> ReclaimReport {
    let token = name;
    let end = Instant::now() + budget;
    let (mut cids, mut sids) = {
        let g = lock(ledger);
        (g.containers.clone(), g.sandboxes.clone())
    };
    let (lc, ls, _) = list_by_selector(c, &selector, end).await;
    lc.into_iter().for_each(|i| push_unique(&mut cids, i));
    ls.into_iter().for_each(|i| push_unique(&mut sids, i));

    let mut report = ReclaimReport {
        token: token.to_owned(),
        ..Default::default()
    };
    for id in cids {
        let _ = call_with_deadline(
            c.stop_container(cri::StopContainerRequest {
                container_id: id.clone(),
                timeout: 2,
            }),
            limit(end),
        )
        .await;
        match call_with_deadline(
            c.remove_container(cri::RemoveContainerRequest {
                container_id: id.clone(),
            }),
            limit(end),
        )
        .await
        {
            Ok(_) => report.reclaimed_containers.push(id.clone()),
            Err(e) if e.code() == PluginErrorCode::NotFound => {}
            Err(_) => report.left_containers.push(id.clone()),
        }
        forget_container(ledger, &id);
    }
    for id in sids {
        let _ = call_with_deadline(
            c.stop_pod_sandbox(cri::StopPodSandboxRequest {
                pod_sandbox_id: id.clone(),
            }),
            limit(end),
        )
        .await;
        match call_with_deadline(
            c.remove_pod_sandbox(cri::RemovePodSandboxRequest {
                pod_sandbox_id: id.clone(),
            }),
            limit(end),
        )
        .await
        {
            Ok(_) => report.reclaimed_sandboxes.push(id.clone()),
            Err(e) if e.code() == PluginErrorCode::NotFound => {}
            Err(_) => report.left_sandboxes.push(id.clone()),
        }
        forget_sandbox(ledger, &id);
    }
    // 取り直し: 一覧に残っているものは、Remove の応答に関わらず残骸にする。
    let (rc, rs, errs) = list_by_selector(c, &selector, end).await;
    report.unverified = errs;
    rc.into_iter()
        .for_each(|i| push_unique(&mut report.left_containers, i));
    rs.into_iter()
        .for_each(|i| push_unique(&mut report.left_sandboxes, i));
    report
}

// ---- 既定の集合で走る自己照合（REPAIR-12。実機を使わない） ----

#[test]
fn reclaim_4142_left_line_exact() {
    let r = ReclaimReport {
        left_sandboxes: vec!["a".repeat(64), "b".repeat(64)],
        left_containers: vec!["c".repeat(64)],
        ..Default::default()
    };
    let want = format!(
        "t: cleanup left cri records sandboxes={},{} containers={}; see docs/setup/cri-record-recovery.md",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64)
    );
    assert_eq!(left_line("t", &r), Some(want));
    let only_sb = ReclaimReport {
        left_sandboxes: vec!["a".into()],
        ..Default::default()
    };
    assert_eq!(
        left_line("t", &only_sb).as_deref(),
        Some(
            "t: cleanup left cri records sandboxes=a containers=; see docs/setup/cri-record-recovery.md"
        )
    );
    assert_eq!(left_line("t", &ReclaimReport::default()), None);
}

#[test]
fn reclaim_4142_list_failure_is_not_clean() {
    let r = ReclaimReport {
        token: "42-7".into(),
        unverified: vec![
            "list_containers: deadline_exceeded".into(),
            "list_pod_sandbox: unavailable".into(),
        ],
        ..Default::default()
    };
    assert!(!r.is_clean());
    assert_eq!(
        left_line("t", &r).as_deref(),
        Some(
            "t: cleanup could not verify cri records token=42-7 reasons=list_containers: deadline_exceeded,list_pod_sandbox: unavailable sandboxes= containers=; see docs/setup/cri-record-recovery.md"
        )
    );
    let with_left = ReclaimReport {
        left_sandboxes: vec!["s".into()],
        ..r
    };
    assert!(left_line("t", &with_left).unwrap().contains("sandboxes=s "));
}

#[test]
fn reclaim_4142_token_is_unique_and_safe() {
    let a = run_token();
    std::thread::sleep(Duration::from_millis(2));
    let b = run_token();
    assert_ne!(a, b);
    assert!(
        a.bytes()
            .all(|x| x.is_ascii_digit() || x.is_ascii_lowercase() || x == b'-')
    );
    let uid = sandbox_uid("uid-attach", &a);
    assert!(uid.len() <= 253, "uid length {}", uid.len());
    assert_eq!(uid, format!("uid-attach-{a}"));
    assert_eq!(labels(&a).get(LABEL_KEY), Some(&a));
}

#[test]
fn reclaim_4285_config_labels_carry_token_and_owner() {
    let m = config_labels(OWNERS[0], "42-7");
    assert_eq!(m.len(), 2);
    assert_eq!(m.get(LABEL_KEY).map(String::as_str), Some("42-7"));
    assert_eq!(m.get(OWNER_KEY).map(String::as_str), Some(OWNERS[0]));
    // selector 用の labels はトークンだけ（部分集合で一致する）。
    assert_eq!(labels("42-7").len(), 1);
    let sel = owner_selector(OWNERS[1]);
    assert_eq!(sel.len(), 1);
    assert_eq!(sel.get(OWNER_KEY).map(String::as_str), Some(OWNERS[1]));
}

#[test]
fn reclaim_4285_owners_are_unique() {
    for (i, a) in OWNERS.iter().enumerate() {
        for b in &OWNERS[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
#[should_panic(expected = "is not in OWNERS")]
fn reclaim_4285_unknown_owner_panics() {
    let _ = config_labels("not-an-owner", "t");
}

#[test]
fn reclaim_4285_plugin_unreachable_boundaries() {
    let unv = ReclaimReport {
        unverified: vec!["list_containers: unavailable".into()],
        ..Default::default()
    };
    assert!(plugin_unreachable(&unv));
    let with_reclaimed = ReclaimReport {
        reclaimed_containers: vec!["c".into()],
        ..unv
    };
    assert!(!plugin_unreachable(&with_reclaimed));
    assert!(!plugin_unreachable(&ReclaimReport::default()));
}

#[test]
fn reclaim_4142_injected_payload_detection() {
    let msg = injected_message("t");
    assert_eq!(
        msg,
        "t: injected failure after StartContainer (expected; reclaim self-check #4142)"
    );
    let s: Box<dyn Any + Send> = Box::new(msg.clone());
    assert!(is_injected("t", s.as_ref()));
    let lit: Box<dyn Any + Send> = Box::new("other");
    assert!(!is_injected("t", lit.as_ref()));
    let other_test: Box<dyn Any + Send> = Box::new(msg);
    assert!(!is_injected("u", other_test.as_ref()));
    let not_str: Box<dyn Any + Send> = Box::new(7u32);
    assert!(!is_injected("t", not_str.as_ref()));
}

#[test]
fn reclaim_4142_scenario_budget_boundaries() {
    let wd = Duration::from_secs(480);
    assert_eq!(
        scenario_budget(Duration::from_secs(100), wd, 2),
        Duration::from_secs(255)
    );
    assert_eq!(
        scenario_budget(Duration::from_secs(100), wd, 1),
        Duration::from_secs(315)
    );
    assert_eq!(
        scenario_budget(Duration::from_secs(470), wd, 1),
        Duration::ZERO
    );
}

#[test]
fn reclaim_4142_ledger_record_and_forget() {
    let l: Ledger = Ledger::default();
    record_sandbox(&l, "s1");
    record_container(&l, "c1");
    record_container(&l, "c2");
    forget_container(&l, "c1");
    let g = lock(&l);
    assert_eq!(g.sandboxes, vec!["s1".to_owned()]);
    assert_eq!(g.containers, vec!["c2".to_owned()]);
}
