//! restart ポリシー評価の結合試験（TASK-159.2・#488・SUP-3・REPAIR-10 (d)・REPAIR-12）。
//!
//! 公開 API のみを外部 crate 視点で使い、ポリシー文字列の解釈から終了分類・再起動判定までを
//! 具体値で確認する（`ProcessExit` → `classify_exit` → `evaluate_restart`）。

use std::num::NonZeroU32;

use fandhe_container_core::oci_runtime::ProcessExit;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::restart::{
    NoRestartReason, RestartDecision, RestartPolicy, StopIntent, classify_exit, evaluate_restart,
};

fn decide(policy: &str, exit: ProcessExit, count: u32, stop: StopIntent) -> RestartDecision {
    let policy: RestartPolicy = policy.parse().expect("valid policy");
    evaluate_restart(policy, classify_exit(exit), count, stop)
}

fn dn(reason: NoRestartReason) -> RestartDecision {
    RestartDecision::DoNotRestart { reason }
}

/// SUP-3: ポリシー文字列の受理と拒否が具体値どおりになる。
#[test]
fn sup3_policy_string_parsing() {
    assert_eq!("no".parse::<RestartPolicy>().unwrap(), RestartPolicy::No);
    assert_eq!(
        "always".parse::<RestartPolicy>().unwrap(),
        RestartPolicy::Always
    );
    assert_eq!(
        "unless-stopped".parse::<RestartPolicy>().unwrap(),
        RestartPolicy::UnlessStopped
    );
    assert_eq!(
        "on-failure".parse::<RestartPolicy>().unwrap(),
        RestartPolicy::OnFailure { max_retries: None }
    );
    assert_eq!(
        "on-failure:3".parse::<RestartPolicy>().unwrap(),
        RestartPolicy::OnFailure {
            max_retries: NonZeroU32::new(3)
        }
    );
    let too_long = format!("on-failure:{}", "9".repeat(64));
    for bad in [
        "",
        "No",
        "on-failure:",
        "on-failure:0",
        "on-failure:-1",
        "on-failure:+1",
        "on-failure:1:2",
        "on-failure:4294967296",
        "restart",
        "always:1",
        too_long.as_str(),
    ] {
        let err = bad.parse::<RestartPolicy>().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "input: {bad:?}");
    }
    assert_eq!(RestartPolicy::default(), RestartPolicy::No);
}

/// SUP-3: 終了状態からポリシー別の再起動判定までが一貫して動く。
#[test]
fn sup3_end_to_end_decisions() {
    let nr = StopIntent::NotRequested;
    assert_eq!(
        decide("no", ProcessExit::Exited(1), 0, nr),
        dn(NoRestartReason::PolicyNo)
    );
    assert_eq!(
        decide("always", ProcessExit::Exited(0), 0, nr),
        RestartDecision::Restart
    );
    assert_eq!(
        decide("unless-stopped", ProcessExit::Signaled(9), 5, nr),
        RestartDecision::Restart
    );
    assert_eq!(
        decide("on-failure", ProcessExit::Exited(0), 0, nr),
        dn(NoRestartReason::ExitedSuccessfully)
    );
    assert_eq!(
        decide("on-failure", ProcessExit::Exited(2), 100, nr),
        RestartDecision::Restart
    );
    assert_eq!(
        decide("on-failure", ProcessExit::Signaled(65), 0, nr),
        dn(NoRestartReason::UnclassifiedExit)
    );
}

/// SUP-3: `on-failure:N` は上限で止まり、明示 stop は全ポリシーで優先される。
#[test]
fn sup3_retry_limit_and_explicit_stop() {
    let nr = StopIntent::NotRequested;
    assert_eq!(
        decide("on-failure:2", ProcessExit::Exited(1), 1, nr),
        RestartDecision::Restart
    );
    assert_eq!(
        decide("on-failure:2", ProcessExit::Exited(1), 2, nr),
        dn(NoRestartReason::RetriesExhausted)
    );
    for p in [
        "no",
        "always",
        "unless-stopped",
        "on-failure",
        "on-failure:3",
    ] {
        assert_eq!(
            decide(p, ProcessExit::Exited(1), 0, StopIntent::Requested),
            dn(NoRestartReason::ExplicitStop),
            "policy: {p}"
        );
    }
    assert_eq!(
        NoRestartReason::RetriesExhausted.as_str(),
        "retries_exhausted"
    );
}
