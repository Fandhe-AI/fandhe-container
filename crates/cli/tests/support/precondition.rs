//! 実機前提試験の「試験環境の前提欠如」を、回帰と 1 行目で見分けられる形にする共有部品
//! （#2957・#2888・CLI-1・CORE-6・REPAIR-12）。
//!
//! # 役割と呼び出し元
//! `start_stop_delete_real`・`delete_cgroup_real`・`start_recover_real` が、委譲 cgroup・Landlock の前提が
//! 欠けたとき、`<試験名>: FAILED: ...` ではなく
//! `<試験名>: PRECONDITION FAILED (test environment, not a <X> regression): ...` の 1 行目で失敗させる。
//! `AGENTS.md`「実機前提テスト」の見分け方と一致する。
//!
//! # 出典
//! `crates/core/tests/support/precondition.rs` の複製（cli の試験は panic ではなく `Result` で失敗を返すため、
//! `failed() -> !` の代わりに `Failure` を返す形にしている）。crate をまたぐ `#[path]` 共有を避けるため。
//! 分類・文言を変えるときは core 側（と supervisor 側の複製）も同時に直す。
//!
//! # 契約
//! - 失敗の範囲は変えない（前提欠如も非 0 終了。成功・skip へ分岐する経路は作らない）
//! - 分類は fail-closed。環境起因と断定できる組だけを `Failure::Precondition` とし、それ以外は `Failure::Other`
//!   （従来の `FAILED:`）のまま失敗させる
//! - メッセージにホストのパス・ユーザー名・ID の値・errno を含めない（固定の英語文と種別だけ）
//! - `self_check` は文字列の照合だけを行い出力しない（`PRECONDITION FAILED` を禁止行とする CI の step があるため）
//!
//! # 取り込み方
//! 各試験が `#[path = "support/precondition.rs"] mod precondition;` で直接取り込む。

use fandhe_container_core::cgroups::CgroupStep;
use fandhe_container_core::landlock::LandlockUnavailable;
use fandhe_container_core::traits::ErrorCode;

/// 前提欠如の種別。`not a <X> regression` の `<X>` と再実行のヒントを決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // 取り込み元によって使う種別が異なる
pub enum Kind {
    /// 委譲された cgroup v2 の部分木が無い。
    DelegatedCgroup,
    /// 範囲写像（`uidmap`・`/etc/subuid`・`/etc/subgid`）の前提が無い。
    SubordinateIds,
    /// Landlock ABI 6 以上が無い。
    Landlock,
}

impl Kind {
    fn regression_label(self) -> &'static str {
        match self {
            Self::DelegatedCgroup => "cgroup delegation",
            Self::SubordinateIds => "subordinate id mapping",
            Self::Landlock => "landlock",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::DelegatedCgroup => {
                "run it inside a delegated cgroup v2 scope, e.g. systemd-run --user --scope -p Delegate=yes <binary> --ignored"
            }
            Self::SubordinateIds => {
                "the helper case needs setuid newuidmap/newgidmap and subuid/subgid entries for the current user (uidmap package)"
            }
            Self::Landlock => "Landlock ABI 6 or newer (Linux 6.12 or newer) is required",
        }
    }
}

/// 試験名（結合試験ではターゲット名 = クレート名）。
fn test_name() -> &'static str {
    env!("CARGO_CRATE_NAME")
}

/// 前提欠如の panic メッセージ。1 行目で前提欠如と回帰を判別できる。`what` は固定の英語文だけを渡す。
pub fn message(kind: Kind, what: &str) -> String {
    let name = test_name();
    format!(
        "{name}: PRECONDITION FAILED (test environment, not a {} regression): {what}.\n\
         hint: {}.\n\
         See AGENTS.md {name}.",
        kind.regression_label(),
        kind.hint()
    )
}

/// 試験シナリオの失敗の種別。`main` が `Precondition` はメッセージをそのまま、`Other` は
/// `<試験名>: FAILED: ...` として標準エラーへ出し、どちらも非 0 で終わる（成功・skip へ分岐しない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // 取り込み元によって読む腕が異なる
pub enum Failure {
    /// 試験環境の前提欠如。値は `message` が組んだ複数行の文面。
    Precondition(String),
    /// 回帰の可能性がある失敗（従来の `FAILED:` 形式）。
    Other(String),
}

impl From<String> for Failure {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for Failure {
    fn from(s: &str) -> Self {
        Self::Other(s.to_owned())
    }
}

/// `DelegatedCgroup::detect` の失敗が試験環境起因か。`CgroupError` は試験から構築できないため、公開フィールドの
/// `code` と `step` の組で判定する。根拠は `crates/core/src/cgroups.rs`:
/// - `detect` が root cgroup かつ非 root を `PermissionDenied`・`CheckDelegation` で拒否する
/// - `check_owned_by` が所有者不一致を `PermissionDenied`・`CheckDelegation` で拒否する
/// - `verify_delegated_scope`・`verify_cgroup2`・`parse_self_cgroup_v2` が cgroup2 でない・domain でない・v2 の行が
///   無いを `FailedPrecondition` で拒否する
/// - `/proc/self/cgroup` の読み取り・cgroup ディレクトリが無いと `NotFound`（`ReadSelfCgroup`・`OpenRoot`）
///
/// 解析失敗（`InvalidArgument`）・`Internal` などは回帰の可能性ありとして `false`。
pub fn classify_detect(code: ErrorCode, step: CgroupStep) -> bool {
    matches!(
        (code, step),
        (ErrorCode::PermissionDenied, CgroupStep::CheckDelegation)
            | (
                ErrorCode::FailedPrecondition,
                CgroupStep::ReadSelfCgroup
                    | CgroupStep::VerifyCgroup2
                    | CgroupStep::CheckDelegation
                    | CgroupStep::OpenRoot
            )
            | (
                ErrorCode::NotFound,
                CgroupStep::ReadSelfCgroup | CgroupStep::OpenRoot
            )
    )
}

/// 委譲 cgroup の検出結果を返す。前提欠如なら `Failure::Precondition`、そうでなければ code・step つきの
/// `Failure::Other`（回帰扱い）で返す。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn delegated_cgroup() -> Result<fandhe_container_core::cgroups::DelegatedCgroup, Failure> {
    match fandhe_container_core::cgroups::DelegatedCgroup::detect() {
        Ok(d) => Ok(d),
        Err(e) if classify_detect(e.code, e.step) => Err(Failure::Precondition(message(
            Kind::DelegatedCgroup,
            "no delegated cgroup v2 subtree is available to the test process",
        ))),
        Err(e) => Err(Failure::Other(format!(
            "detect delegated cgroup v2: code={:?} step={:?}: {}",
            e.code, e.step, e.message
        ))),
    }
}

/// subuid / subgid / helper の読み取り失敗が試験環境起因か（ファイル・helper が無い、読めない、helper の権限が足りない）。
/// 内容の解析失敗（`InvalidArgument`）は回帰の可能性ありとして `false`。
#[allow(dead_code)] // cli の試験は範囲写像を使わない（core・supervisor との照合の揃えのため残す）
pub fn classify_subid_code(code: ErrorCode) -> bool {
    matches!(code, ErrorCode::NotFound | ErrorCode::PermissionDenied)
}

/// Landlock の検出失敗が試験環境起因か。カーネル・起動設定・ABI 不足だけを前提欠如とし、
/// 応答不正・非対応アーキテクチャ・その他の errno は回帰の可能性ありとして `false`。
pub fn classify_landlock(reason: &LandlockUnavailable) -> bool {
    matches!(
        reason,
        LandlockUnavailable::KernelLacksLandlock
            | LandlockUnavailable::DisabledAtBoot
            | LandlockUnavailable::AbiTooOld { .. }
    )
}

/// Landlock ABI 6 以上を検出する。前提欠如なら `Failure::Precondition`、そうでなければ `Failure::Other`。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn landlock_support() -> Result<fandhe_container_core::landlock::LandlockSupport, Failure> {
    match fandhe_container_core::landlock::detect_landlock_abi() {
        Ok(s) => Ok(s),
        Err(e) if classify_landlock(&e.reason) => Err(Failure::Precondition(message(
            Kind::Landlock,
            "the kernel does not provide Landlock ABI 6 or newer",
        ))),
        Err(e) => Err(Failure::Other(format!("detect Landlock ABI: {e}"))),
    }
}

/// 分類とメッセージの自己照合（各試験の `main` から既定集合でも毎回走らせる。出力はしない。#2888・REPAIR-12）。
pub fn self_check() {
    let name = test_name();
    let first = |kind: Kind, what: &str| message(kind, what).lines().next().map(str::to_owned);
    assert_eq!(
        first(Kind::DelegatedCgroup, "x"),
        Some(format!(
            "{name}: PRECONDITION FAILED (test environment, not a cgroup delegation regression): x."
        ))
    );
    assert_eq!(
        first(
            Kind::SubordinateIds,
            "no subuid entry exists for the current user"
        ),
        Some(format!(
            "{name}: PRECONDITION FAILED (test environment, not a subordinate id mapping regression): no subuid entry exists for the current user."
        ))
    );
    assert_eq!(
        first(Kind::Landlock, "x"),
        Some(format!(
            "{name}: PRECONDITION FAILED (test environment, not a landlock regression): x."
        ))
    );
    let m = message(Kind::DelegatedCgroup, "x");
    assert!(m.contains("--ignored"), "{m}");
    assert!(m.ends_with(&format!("See AGENTS.md {name}.")), "{m}");

    // 環境起因の組は前提欠如、解析失敗・内部エラーは回帰の可能性ありとして汎用 panic のまま。
    assert!(classify_detect(
        ErrorCode::PermissionDenied,
        CgroupStep::CheckDelegation
    ));
    assert!(classify_detect(
        ErrorCode::FailedPrecondition,
        CgroupStep::VerifyCgroup2
    ));
    assert!(classify_detect(ErrorCode::NotFound, CgroupStep::OpenRoot));
    assert!(!classify_detect(
        ErrorCode::InvalidArgument,
        CgroupStep::ReadSelfCgroup
    ));
    assert!(!classify_detect(
        ErrorCode::Internal,
        CgroupStep::CheckDelegation
    ));
    assert!(!classify_detect(
        ErrorCode::PermissionDenied,
        CgroupStep::CreateChild
    ));
    assert_eq!(Failure::from("x"), Failure::Other("x".to_owned()));
    assert_eq!(
        Failure::from(String::from("y")),
        Failure::Other("y".to_owned())
    );
    assert!(classify_subid_code(ErrorCode::NotFound));
    assert!(classify_subid_code(ErrorCode::PermissionDenied));
    assert!(!classify_subid_code(ErrorCode::InvalidArgument));
    assert!(!classify_subid_code(ErrorCode::Internal));
    assert!(classify_landlock(&LandlockUnavailable::KernelLacksLandlock));
    assert!(classify_landlock(&LandlockUnavailable::DisabledAtBoot));
    assert!(classify_landlock(&LandlockUnavailable::AbiTooOld {
        detected: 1,
        required: 6
    }));
    assert!(!classify_landlock(
        &LandlockUnavailable::InvalidKernelResponse { raw: 0 }
    ));
    assert!(!classify_landlock(
        &LandlockUnavailable::UnsupportedArchitecture
    ));
}
