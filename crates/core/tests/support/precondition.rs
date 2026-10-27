//! 実機前提試験の「試験環境の前提欠如」を、回帰と 1 行目で見分けられる形にする共有部品の正本
//! （#3028・#2888・#2957・CORE-5・SEC-4・REPAIR-1・REPAIR-12）。
//!
//! # 役割と呼び出し元
//! core・supervisor・cli・oci の実機前提試験が、委譲 cgroup・範囲写像の前提（`uidmap`・`/etc/subuid`・
//! `/etc/subgid`）・Landlock の前提が欠けたとき、`expect` の文言ではなく
//! `<試験名>: PRECONDITION FAILED (test environment, not a <X> regression): ...` の 1 行目で失敗させる。
//! - core: `production_launcher` と rootless 系・cgroup 系（`cgroup_*`・`cgroups*` 等 23 本。#2956）。
//!   `cgroups_release_agent` の既定試験 `sec6_task35_*` が行う `DelegatedCgroup::detect()` の拒否そのものの検証
//!   （CORE-4・SEC-6）は、検証が逆になるため通さない
//! - supervisor: `exec_setns_join`・`exec_identify_cgroup`（panic 版を直接取り込む）
//! - cli: `start_stop_delete_real` ほか 3 本（`crates/cli/tests/support/precondition.rs` の薄いアダプタ経由で
//!   `Result` 版を使う）
//! - oci: `pull_e2e` の実機モード（委譲 cgroup・opt-in 時の範囲写像。OCI-1）
//!
//! # 契約
//! - 2 層を持つ。`try_*` は `Result<_, Failure>` を返し、`Failure::Precondition` は前提欠如、`Failure::Other` は
//!   回帰の可能性ありの失敗（従来の汎用メッセージ）。`failed`・`delegated_cgroup` 等の panic 版は `try_*` の薄い包み
//! - 失敗の範囲は変えない（前提欠如は従来どおり非 0 終了。成功・skip へ分岐する経路は作らない）
//! - 分類は fail-closed。環境起因と断定できる組だけを前提欠如とし、それ以外は回帰の可能性ありとして
//!   `Failure::Other` のまま失敗させる（`classify_*` が `false` を返す）
//! - メッセージにホストのパス・ユーザー名・ID の値・errno を含めない（固定の英語文と種別だけ）
//! - メッセージは標準出力・標準エラーへ出さない（`PRECONDITION FAILED` を禁止行とする CI の step があるため。
//!   `self_check` は文字列の照合だけを行う）
//!
//! # 置き場所の判断
//! `#[path]` 共有を選び、補助 crate にしない。`test_name()` が `env!("CARGO_CRATE_NAME")` で試験名を得るため、
//! `#[path]` なら取り込む試験バイナリごとに正しい名前が 1 行目に入る（補助 crate では全メッセージが補助 crate の
//! 名前になり `<試験名>: PRECONDITION FAILED` の契約が壊れる）。依存の追加も要らない（`minimal_rootfs.rs` と同じ判断）。
//!
//! # 取り込み方
//! core: `real_entry.rs` が `pub mod precondition` として取り込む。`real_entry.rs` を使わない試験は
//! `#[path = "support/precondition.rs"] mod precondition;`。他 crate は
//! `#[path = "../../core/tests/support/precondition.rs"]` で直接取り込む（cli はアダプタ経由）。
//! libtest の試験は ignore しない `repair12_precondition_self_check` で、`harness = false` の試験は
//! `main` の先頭で `self_check()` を呼び、既定の `cargo test` で自己照合を走らせる。
//! 取り込み元ごとに使わない項目があるため、該当項目には `#[allow(dead_code)]` を付ける。

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

/// 試験シナリオの失敗の種別。panic 版は両方を `panic!` にし、cli のアダプタは `Result` のまま `FAILED:` 行へ流す。
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // 取り込み元によって読む腕が異なる
pub enum Failure {
    /// 試験環境の前提欠如。値は `message` が組んだ複数行の文面。
    Precondition(String),
    /// 回帰の可能性がある失敗（従来の汎用メッセージ）。
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

/// `Failure` を panic にする（panic 版の共通の終端。成功・skip へ分岐しない）。
#[allow(dead_code)] // 取り込み元によっては使わない
fn panic_on(f: Failure) -> ! {
    match f {
        Failure::Precondition(m) | Failure::Other(m) => panic!("{m}"),
    }
}

/// 前提欠如として失敗する（panic。成功へ分岐しない）。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn failed(kind: Kind, what: &str) -> ! {
    panic!("{}", message(kind, what))
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
pub fn try_delegated_cgroup() -> Result<fandhe_container_core::cgroups::DelegatedCgroup, Failure> {
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

/// `try_delegated_cgroup` の panic 版。前提欠如なら PRECONDITION FAILED で、そうでなければ汎用 panic で失敗する。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn delegated_cgroup() -> fandhe_container_core::cgroups::DelegatedCgroup {
    try_delegated_cgroup().unwrap_or_else(|f| panic_on(f))
}

/// subuid / subgid / helper の読み取り失敗が試験環境起因か（ファイル・helper が無い、読めない、helper の権限が足りない）。
/// 内容の解析失敗（`InvalidArgument`）は回帰の可能性ありとして `false`。
pub fn classify_subid_code(code: ErrorCode) -> bool {
    matches!(code, ErrorCode::NotFound | ErrorCode::PermissionDenied)
}

/// 範囲写像の helper ケースの前提（`newuidmap` / `newgidmap`・subuid / subgid の自ユーザー行）を確かめる。
/// 欠けていれば `Failure::Precondition`。失敗の文言を変えるためだけの検査で、検証を省く経路は作らない。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn try_require_subordinate_ids(euid: u32) -> Result<(), Failure> {
    use fandhe_container_core::rootless::{HelperPaths, SubIdOwner, load_subordinate_ids};
    use std::path::Path;

    let pre = |what: &str| Failure::Precondition(message(Kind::SubordinateIds, what));
    // `USER` は任意。未設定でも数値 uid だけで所有者を作れ、一致する行が無ければ下で前提欠如にする。
    let name = std::env::var("USER").ok().filter(|n| !n.is_empty());
    if let Err(e) = HelperPaths::system_default() {
        if classify_subid_code(e.code) {
            return Err(pre(
                "newuidmap/newgidmap are missing or not usable as trusted helpers",
            ));
        }
        return Err(Failure::Other(format!(
            "resolve newuidmap/newgidmap: code={:?}: {}",
            e.code, e.message
        )));
    }
    let owner =
        SubIdOwner::new(euid, name).map_err(|e| Failure::Other(format!("subid owner: {e:?}")))?;
    for (file, label) in [("/etc/subuid", "subuid"), ("/etc/subgid", "subgid")] {
        match load_subordinate_ids(Path::new(file), &owner) {
            Ok(r) if r.is_empty() => {
                return Err(pre(&format!(
                    "no {label} entry exists for the current user"
                )));
            }
            Ok(_) => {}
            Err(e) if classify_subid_code(e.code) => {
                return Err(pre(&format!("the {label} file is missing or unreadable")));
            }
            Err(e) => {
                return Err(Failure::Other(format!(
                    "load {file}: code={:?}: {}",
                    e.code, e.message
                )));
            }
        }
    }
    Ok(())
}

/// `try_require_subordinate_ids` の panic 版。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn require_subordinate_ids(euid: u32) {
    if let Err(f) = try_require_subordinate_ids(euid) {
        panic_on(f)
    }
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
pub fn try_landlock_support() -> Result<fandhe_container_core::landlock::LandlockSupport, Failure> {
    match fandhe_container_core::landlock::detect_landlock_abi() {
        Ok(s) => Ok(s),
        Err(e) if classify_landlock(&e.reason) => Err(Failure::Precondition(message(
            Kind::Landlock,
            "the kernel does not provide Landlock ABI 6 or newer",
        ))),
        Err(e) => Err(Failure::Other(format!("detect Landlock ABI: {e}"))),
    }
}

/// `try_landlock_support` の panic 版。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn landlock_support() -> fandhe_container_core::landlock::LandlockSupport {
    try_landlock_support().unwrap_or_else(|f| panic_on(f))
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
