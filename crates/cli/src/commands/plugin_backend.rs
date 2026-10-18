//! macOS / Windows のバックエンドを plugin 発見・登録機構（PLUG-4）経由で解決する入口（TASK-79.4・CLI-1・PLUG-4・PLUG-11・MS-6）。
//!
//! `create_start::production_runtime` が非 Linux でだけ呼ぶ。Linux は plugin を介さず core を直接呼ぶ。
//! 本 CLI は `crates/platform-macos`・`crates/platform-windows` およびそれらの plugin crate へ直接依存せず
//! （`make check-cli-backend-deps` が `cargo tree` で機械判定する）、core の発見
//! （`plugin_discovery`）・レジストリ・信頼性検証（`plugin_trust`）だけを使う。
//!
//! 段階: 発見 → レジストリ登録 → 期待名の plugin を引く → 信頼性検証（所有者・モード・許可済みハッシュ）。
//! 各段階の失敗は固定文言の [`TraitError`] に落とし、パス・plugin 名・検証失敗の詳細は出力へ反射しない
//! （インジェクション・情報漏えい回避）。未検証の候補は spawn も接続もしない（fail-closed。PLUG-11）。
//!
//! # 監査（SEC-4・PLUG-11・#2013）
//!
//! 信頼性検証の拒否（所有者・モード・ハッシュ・未実装方式）は core の `verify_candidate_audited` で検証し、
//! 拒否 1 回につき層 `plugin_trust` の監査レコードを 1 件、`AuditSink` へ記録する。本番の記録先は
//! `unavailable` が `FileAuditSink::open_in_state_root`（`<状態ルート>/@audit.log`）で作る。記録先を作れない
//! ときは、常にその `TraitError` を返す私的な sink を渡し、`AuditDelivery::SinkFailed` として扱う（黙って捨てない。
//! 何もしない sink は作らない）。記録の成否は CLI の終了コード・構造化エラーを変えない（fail-closed）。
//! 記録の結果（delivery）は stderr に出さない（出力の 3 OS 互換を保つ。両経路の失敗の通知は `FileAuditSink`
//! 自身が出す）。記録に `container_id` は付けない: 検証はコンテナを特定する前にバックエンドを解決するために走り
//! （create・start・stop・delete・list・logs のどれでも）、特定のコンテナに属さないため。
//!
//! 未実装・簡易実装（REPAIR-3。実装済みを装わない）:
//! - 非 Linux の既定探索先は空（core が未確定のため）で、実環境では「候補なし」になる。
//! - 非 Linux の信頼性検証は core が常に `Unsupported` で拒否する（PLUG-11 の非 Linux 実装待ち）。この拒否も
//!   `unsupported` として記録を試みるが、非 Linux では `FileStateStore::open` が `Unimplemented` を返し記録先が
//!   作れないため、記録は `SinkFailed` になる（`FileStateStore` の非 Linux 実装待ち）。
//! - 許可済みハッシュ一覧の配置・指定方法が未確定のため一覧は既定の空（全件拒否）のままで、読み込み経路は無い。
//! - 検証を通過した plugin の起動と RPC は未実装。core 側の型つき `ContainerRuntime` proxy と spawn の配線は
//!   TASK-114、CLI 経由の 3 OS 最終確認は TASK-125。RPC を配線する際は REPAIR-5 のタイムアウトを必須とする。
//!
//! したがって [`backend_failure`] は現状必ず失敗を返す。
//!
//! # 失敗の識別子（C1・TASK-79.4 追補）
//!
//! plugin 解決の失敗は [`BackendFailure`] の閉じた列挙と固定文言表（SSOT）に集約する。create 系は文言がそのまま
//! stderr へ届き、`list` / `logs` は `list_logs::store_open_failure` が [`BackendFailure::classify`] で
//! 表との完全一致を確かめたときだけ同じ定数を出す（「未導入」と「信頼性検証の拒否」を区別できる）。
//! 表に無い失敗（`--root` 不正・発見の I/O エラー等）は従来どおり汎用文言に落とし、core の
//! `TraitError::message` を出力へ流さない。
//!
//! # 配線時に再評価する事項（TASK-114・TASK-122）
//!
//! - PATH 由来の候補の扱い（A1）: [`backend_failure`] は `PluginDirKind::Path` の候補も
//!   `PluginRegistry::from_candidates` へ渡しており、現状は許可一覧が空で全件拒否になることに頼っている。
//!   許可済みハッシュ一覧を配線すると PATH 由来もハッシュ一致で採用され得るため、登録前に除外するか
//!   採用するかをその時点で明示的に決める（core の `plugin_discovery` の契約も参照）。
//! - `PluginTrustError` の写像（C2）: その `Display` と `From<PluginTrustError> for TraitError` は拒否対象の
//!   パスを含む。出力へ流すときは `?` で `TraitError` へ変換せず、`kind()` だけを本 module の固定文言表へ
//!   写し、パス・plugin 名を出力へ反射しないこと（配線時のレビュー観点）。

use std::io::Write;

use fandhe_container_core::audit_log::{AuditRecord, AuditSink, FileAuditSink};
use fandhe_container_core::plugin_discovery::{
    DiscoveryOptions, DiscoveryReport, PathSearchPolicy, PluginRegistry,
    discover_default_with_options, write_path_warnings,
};
use fandhe_container_core::plugin_trust::{
    PluginTrustErrorKind, PluginVerificationMethod, verify_candidate_audited,
};
use fandhe_container_core::state_store::StateRoot;
use fandhe_container_core::traits::{ErrorCode, TraitError};

use super::args::GlobalArgs;

/// plugin 解決の失敗種別（閉じた列挙）。コードと固定文言の対応表の SSOT。
///
/// `backend_failure` / `unavailable` が生成し、`list_logs::store_open_failure` が
/// [`BackendFailure::classify`] で逆引きする。文言はエスケープ不要の英語定数のみで、パス・plugin 名を含まない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackendFailure {
    NotInstalled,
    TrustUnsupported,
    Untrusted,
    NotInvokable,
    NoBackend,
}

impl BackendFailure {
    /// 全 variant（`classify` の走査対象。表の追加漏れをテストで検出する）。
    pub(super) const ALL: [Self; 5] = [
        Self::NotInstalled,
        Self::TrustUnsupported,
        Self::Untrusted,
        Self::NotInvokable,
        Self::NoBackend,
    ];

    pub(super) fn code(self) -> ErrorCode {
        match self {
            Self::NotInstalled => ErrorCode::FailedPrecondition,
            Self::TrustUnsupported | Self::NotInvokable | Self::NoBackend => {
                ErrorCode::Unimplemented
            }
            Self::Untrusted => ErrorCode::PermissionDenied,
        }
    }

    pub(super) fn message(self) -> &'static str {
        match self {
            Self::NotInstalled => MSG_NOT_INSTALLED,
            Self::TrustUnsupported => MSG_TRUST_UNSUPPORTED,
            Self::Untrusted => MSG_UNTRUSTED,
            Self::NotInvokable => MSG_NOT_INVOKABLE,
            Self::NoBackend => MSG_NO_BACKEND,
        }
    }

    pub(super) fn into_error(self) -> TraitError {
        TraitError::new(self.code(), self.message())
    }

    /// コードと文言が表と完全一致するときだけ種別を返す（それ以外は `None`）。
    pub(super) fn classify(e: &TraitError) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.code() == e.code() && k.message() == e.message())
    }
}

const MSG_NOT_INSTALLED: &str = "platform backend plugin is not installed";
const MSG_TRUST_UNSUPPORTED: &str = "plugin trust verification is not implemented on this platform";
const MSG_UNTRUSTED: &str = "platform backend plugin failed trust verification";
const MSG_NOT_INVOKABLE: &str = "plugin backend invocation is not implemented";
const MSG_NO_BACKEND: &str = "no platform backend plugin exists for this platform";

/// ホスト OS が必要とするバックエンド plugin（閉じた列挙。外部入力から plugin 名を組み立てない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackendPlugin {
    Macos,
    Windows,
}

impl BackendPlugin {
    /// レジストリのキー（`fandhe-container-plugin-` 接頭辞を除いた名前。PLUG-4）。
    pub(super) fn name(self) -> &'static str {
        match self {
            BackendPlugin::Macos => "macos",
            BackendPlugin::Windows => "windows",
        }
    }
}

/// ホスト OS に対応するバックエンド（macOS / Windows 以外は `None`）。CLI-1 の OS 分岐はここに局所化する。
///
/// Linux では module が単体テスト時だけコンパイルされ、本番経路（[`unavailable`]）は呼ばれないため dead_code を許す。
/// OS 別のバックエンド振り分けであり OS 固有設定（CLI-2・TASK-80.2）ではない。setup module は参照しない。
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn host_backend() -> Option<BackendPlugin> {
    if cfg!(target_os = "macos") {
        Some(BackendPlugin::Macos)
    } else if cfg!(windows) {
        Some(BackendPlugin::Windows)
    } else {
        None
    }
}

/// 発見結果を登録・検証し、現時点で到達できる段階の失敗を返す（常に失敗。モジュール doc 参照）。
///
/// 対応表: 候補なし → `FailedPrecondition`、非 Linux の検証未実装 → `Unimplemented`、
/// 検証・ハッシュ照合の拒否 → `PermissionDenied`、全検証通過後（起動未実装）→ `Unimplemented`。
/// 同名候補の shadowed へは自動フォールバックしない（レジストリの契約どおり）。
///
/// PATH 由来の候補もレジストリへ渡す。許可一覧の配線時に採否を再評価する（モジュール doc 参照。TASK-114・TASK-122）。
///
/// 信頼性検証の拒否は `sink` へ 1 件記録する（SEC-4・#2013。モジュール doc の「監査」）。記録の成否は戻り値を変えない。
pub(super) fn backend_failure(
    backend: BackendPlugin,
    report: DiscoveryReport,
    sink: &dyn AuditSink,
) -> TraitError {
    let (candidates, _warnings) = report.into_parts();
    let registry = match PluginRegistry::from_candidates(candidates) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let Some(candidate) = registry.get(backend.name()) else {
        return BackendFailure::NotInstalled.into_error();
    };
    // 所有者・モード・ハッシュの順の検証と、どの段の拒否の記録も 1 回の呼び出しで行う。
    // 既定は空の許可一覧（全件拒否）。一覧の読み込み経路は仕様確定まで作らない。
    match verify_candidate_audited(candidate, &PluginVerificationMethod::default(), sink) {
        Ok(_) => BackendFailure::NotInvokable.into_error(),
        Err(rejection) if rejection.error.kind() == PluginTrustErrorKind::Unsupported => {
            BackendFailure::TrustUnsupported.into_error()
        }
        Err(_) => BackendFailure::Untrusted.into_error(),
    }
}

/// 記録先を作れなかったときに渡す sink。`record` が常に作成時の失敗を返し、拒否の記録は `SinkFailed` になる
/// （黙って捨てない。拒否は覆らない。#2013）。
struct UnavailableAuditSink(TraitError);

impl AuditSink for UnavailableAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
        Err(self.0.clone())
    }
}

/// 本番の記録先を作る（`<状態ルート>/@audit.log`。作れなければ常に失敗する sink）。
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn production_audit_sink(global: &GlobalArgs) -> Box<dyn AuditSink> {
    match FileAuditSink::open_in_state_root(global.root.clone()) {
        Ok(sink) => Box::new(sink),
        Err(e) => Box::new(UnavailableAuditSink(e)),
    }
}

/// 非 Linux の本番経路。`--root` 検証 → 発見（`PATH` 警告は stderr へ）→ 記録先の作成 → [`backend_failure`]。
///
/// Linux では module が単体テスト時だけコンパイルされ、本番経路からは呼ばれないため dead_code を許す。
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn unavailable(global: &GlobalArgs) -> TraitError {
    // Linux の `open_store` と揃え、不正な `--root`（相対パス・`..`）は plugin 解決より先に INVALID_ARGUMENT で拒否する。
    if let Some(root) = global.root.clone()
        && let Err(e) = StateRoot::from_override(root)
    {
        return e;
    }
    let Some(backend) = host_backend() else {
        return BackendFailure::NoBackend.into_error();
    };
    let policy = if global.plugin_path_search {
        PathSearchPolicy::Enabled
    } else {
        PathSearchPolicy::Disabled
    };
    let options = DiscoveryOptions::new().with_path_search(policy);
    match discover_default_with_options(&options) {
        Ok(report) => {
            let mut err = std::io::stderr();
            // 警告の出力失敗は本来の失敗を隠さないよう無視する。
            let _ = write_path_warnings(&report, &mut err);
            let _ = err.flush();
            let sink = production_audit_sink(global);
            backend_failure(backend, report, sink.as_ref())
        }
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::audit_log::{AuditEvent, AuditLayer, AuditPid, AuditTimestamp};
    use fandhe_container_core::plugin_discovery::{
        PATH_WARNING_CODE, PluginDirKind, PluginSearchDir, discover_with_options,
    };
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// 記録を集めるだけの sink（件数に上限を置く）。
    struct CollectSink(Mutex<Vec<AuditRecord>>);
    impl CollectSink {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }
        fn records(&self) -> Vec<AuditRecord> {
            self.0.lock().map(|g| g.clone()).unwrap_or_default()
        }
    }
    impl AuditSink for CollectSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            let mut g = self
                .0
                .lock()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?;
            if g.len() >= 8 {
                return Err(TraitError::new(ErrorCode::Internal, "sink full"));
            }
            g.push(record.clone());
            Ok(())
        }
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "fc-cli-pb-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("tmp");
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// C2: 失敗の message は一時ディレクトリのパスも plugin 名も含まない（出力へ反射しない）。
    fn assert_no_path_or_name(e: &TraitError, tmp: &Tmp) {
        let dir = tmp.0.to_string_lossy();
        assert!(!e.message().contains(dir.as_ref()), "{}", e.message());
        assert!(!e.message().contains("fandhe-container-plugin"));
        assert!(!e.message().contains("macos"));
    }

    fn exe_name(name: &str) -> String {
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        format!("fandhe-container-plugin-{name}{suffix}")
    }

    fn report_with(tmp: &Tmp, names: &[&str]) -> DiscoveryReport {
        for n in names {
            std::fs::write(tmp.0.join(exe_name(n)), b"stub").expect("write");
        }
        let dirs = [PluginSearchDir::new(PluginDirKind::System, tmp.0.clone())];
        discover_with_options(&dirs, None, &DiscoveryOptions::new()).expect("discover")
    }

    /// PLUG-4: 候補が無ければ FailedPrecondition（終了コード 5）。
    #[test]
    fn plug4_no_candidates_is_failed_precondition() {
        let tmp = Tmp::new("empty");
        let e = backend_failure(
            BackendPlugin::Macos,
            report_with(&tmp, &[]),
            &CollectSink::new(),
        );
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_NOT_INSTALLED);
    }

    /// PLUG-4: 別名の plugin だけがあっても期待名が無ければ FailedPrecondition。
    #[test]
    fn plug4_other_plugin_only_is_failed_precondition() {
        let tmp = Tmp::new("other");
        let e = backend_failure(
            BackendPlugin::Windows,
            report_with(&tmp, &["other"]),
            &CollectSink::new(),
        );
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    }

    /// PLUG-11（Linux）: 一時ディレクトリは祖先（sticky の /tmp 等）が不適格なため拒否 = PermissionDenied。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_untrusted_location_is_permission_denied() {
        let tmp = Tmp::new("untrusted");
        let e = backend_failure(
            BackendPlugin::Macos,
            report_with(&tmp, &["macos"]),
            &CollectSink::new(),
        );
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
        assert_eq!(e.message(), MSG_UNTRUSTED);
        assert_no_path_or_name(&e, &tmp);
    }

    /// 置き場を group/other 書き込み可（0777）にした決定的な拒否の fixture。
    #[cfg(target_os = "linux")]
    fn writable_dir_report(tag: &str) -> (Tmp, DiscoveryReport) {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = Tmp::new(tag);
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let report = report_with(&tmp, &["macos"]);
        (tmp, report)
    }

    /// SEC-4・PLUG-11（#2013, Linux）: 信頼性検証の拒否は層 `plugin_trust` の記録 1 件になり、理由は
    /// `group_or_other_writable`、パスは置き場かその祖先、`container_id` は付かない。CLI の失敗は従来どおり。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2013_untrusted_rejection_is_recorded_once() {
        let (tmp, report) = writable_dir_report("audit-rec");
        let sink = CollectSink::new();
        let e = backend_failure(BackendPlugin::Macos, report, &sink);
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
        assert_eq!(e.message(), MSG_UNTRUSTED);
        assert_no_path_or_name(&e, &tmp);
        let recs = sink.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::PluginTrust);
        assert_eq!(
            recs[0].reason().map(|r| r.as_str().to_string()).as_deref(),
            Some("group_or_other_writable")
        );
        let path = recs[0].path().expect("path");
        assert!(
            tmp.0.starts_with(path) || path.starts_with(&tmp.0),
            "{path:?}"
        );
        assert_eq!(recs[0].container_id(), None);
    }

    /// SEC-4（#2013, Linux）: 記録先を作れない sink（常に失敗）でも拒否は覆らず、コードと文言は記録できる sink と
    /// 完全に同じ。候補なしの失敗は検証に至らないので記録 0 件。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2013_sink_failure_does_not_change_the_rejection() {
        let (_tmp, report) = writable_dir_report("audit-fail");
        let failing = UnavailableAuditSink(TraitError::new(ErrorCode::Internal, "x"));
        let e = backend_failure(BackendPlugin::Macos, report, &failing);
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
        assert_eq!(e.message(), MSG_UNTRUSTED);

        let tmp = Tmp::new("audit-none");
        let sink = CollectSink::new();
        let e = backend_failure(BackendPlugin::Macos, report_with(&tmp, &[]), &sink);
        assert_eq!(e.message(), MSG_NOT_INSTALLED);
        assert!(sink.records().is_empty());
    }

    /// SEC-4（#2013）: 記録先を作れなかったときの sink は、`record` が保持した `TraitError` を常にそのまま返す。
    #[test]
    fn sec4_2013_unavailable_audit_sink_keeps_its_error() {
        let want = TraitError::new(ErrorCode::Unimplemented, "no store");
        let sink = UnavailableAuditSink(want.clone());
        let rec = AuditRecord::new(
            AuditTimestamp::from_unix_duration(std::time::Duration::from_secs(1)),
            AuditPid::new(1).expect("pid"),
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        assert_eq!(sink.record(&rec), Err(want));
    }

    /// PLUG-11（非 Linux）: 信頼性検証が未実装のため Unimplemented（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn plug11_non_linux_trust_unimplemented() {
        let tmp = Tmp::new("unsupported");
        let sink = CollectSink::new();
        let e = backend_failure(BackendPlugin::Macos, report_with(&tmp, &["macos"]), &sink);
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(e.message(), MSG_TRUST_UNSUPPORTED);
        assert_no_path_or_name(&e, &tmp);
        // 非 Linux の拒否 `unsupported` も記録を試みる（SEC-4・#2013）。
        let recs = sink.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::PluginTrust);
        assert_eq!(
            recs[0].reason().map(|r| r.as_str().to_string()).as_deref(),
            Some("unsupported")
        );
    }

    /// PLUG-11: PATH opt-in の候補は警告 1 行ずつ出て、名前一致だけでは採用されない（検証で拒否される）。
    #[test]
    fn plug11_path_candidates_warn_and_are_not_adopted() {
        let tmp = Tmp::new("path");
        std::fs::write(tmp.0.join(exe_name("macos")), b"stub").expect("write");
        std::fs::write(tmp.0.join(exe_name("windows")), b"stub").expect("write");
        let opts = DiscoveryOptions::new().with_path_search(PathSearchPolicy::Enabled);
        let report = discover_with_options(&[], Some(tmp.0.as_os_str()), &opts).expect("discover");
        let mut out = Vec::new();
        write_path_warnings(&report, &mut out).expect("warn");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| l.contains(PATH_WARNING_CODE)));
        // A1 の前提固定（配線時に再評価: この前提を変えたら doc も見直す）。PATH 由来の候補もレジストリに登録される。
        let registered =
            PluginRegistry::from_candidates(report.candidates().iter().cloned()).expect("registry");
        let entry = registered.get("macos").expect("macos registered");
        assert_eq!(entry.origin(), PluginDirKind::Path);
        // PATH 由来の候補も信頼性検証を通る。Linux では一時ディレクトリが不適格、非 Linux は未実装で拒否。
        let e = backend_failure(BackendPlugin::Macos, report, &CollectSink::new());
        assert!(matches!(
            e.code(),
            ErrorCode::PermissionDenied | ErrorCode::Unimplemented
        ));
    }

    /// CLI-1: ホスト OS ごとのバックエンド選択。
    #[test]
    fn cli1_host_backend_per_os() {
        let expected = if cfg!(target_os = "macos") {
            Some(BackendPlugin::Macos)
        } else if cfg!(windows) {
            Some(BackendPlugin::Windows)
        } else {
            None
        };
        assert_eq!(host_backend(), expected);
        assert_eq!(BackendPlugin::Macos.name(), "macos");
        assert_eq!(BackendPlugin::Windows.name(), "windows");
    }

    /// CLI-1・ERR-2: 不正な `--root`（相対パス・`..`）は plugin 解決より先に INVALID_ARGUMENT で拒否される。
    #[test]
    fn err2_unavailable_rejects_invalid_root_first() {
        for root in ["rel/root", "../x"] {
            let global = GlobalArgs {
                root: Some(PathBuf::from(root)),
                ..GlobalArgs::default()
            };
            let e = unavailable(&global);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "root={root}");
        }
    }

    /// 固定文言は引用符・バックスラッシュ・制御文字を含まない（出力への反射・エスケープ不要）。
    #[test]
    fn fixed_messages_need_no_escaping() {
        for k in BackendFailure::ALL {
            assert!(!k.message().contains(['"', '\\']));
            assert!(!k.message().chars().any(char::is_control));
        }
    }

    /// C1・REPAIR-12: 失敗種別ごとのコードと文言を具体値で固定する。
    #[test]
    fn c1_backend_failure_table_is_exact() {
        let table = [
            (
                BackendFailure::NotInstalled,
                ErrorCode::FailedPrecondition,
                "platform backend plugin is not installed",
            ),
            (
                BackendFailure::TrustUnsupported,
                ErrorCode::Unimplemented,
                "plugin trust verification is not implemented on this platform",
            ),
            (
                BackendFailure::Untrusted,
                ErrorCode::PermissionDenied,
                "platform backend plugin failed trust verification",
            ),
            (
                BackendFailure::NotInvokable,
                ErrorCode::Unimplemented,
                "plugin backend invocation is not implemented",
            ),
            (
                BackendFailure::NoBackend,
                ErrorCode::Unimplemented,
                "no platform backend plugin exists for this platform",
            ),
        ];
        assert_eq!(table.len(), BackendFailure::ALL.len());
        for (k, code, msg) in table {
            assert_eq!(k.code(), code);
            assert_eq!(k.message(), msg);
        }
    }

    /// C1: 表の逆引きは完全一致のみ。任意の文言・別コードは `None`（出力へ素通ししない）。
    #[test]
    fn c1_classify_round_trips_and_rejects_others() {
        for k in BackendFailure::ALL {
            assert_eq!(BackendFailure::classify(&k.into_error()), Some(k));
        }
        for e in [
            TraitError::new(ErrorCode::FailedPrecondition, "failed precondition"),
            TraitError::new(
                ErrorCode::Unimplemented,
                "platform backend plugin is not installed",
            ),
            TraitError::new(ErrorCode::FailedPrecondition, "detail"),
        ] {
            assert_eq!(BackendFailure::classify(&e), None);
        }
    }

    /// C1: 5 文言は互いに異なり、汎用文言（`failure_message`）とも一致しない。
    #[test]
    fn c1_backend_messages_are_distinct() {
        let msgs: Vec<&str> = BackendFailure::ALL.iter().map(|k| k.message()).collect();
        for (i, a) in msgs.iter().enumerate() {
            for b in &msgs[i + 1..] {
                assert_ne!(a, b);
            }
            for k in BackendFailure::ALL {
                assert_ne!(*a, crate::commands::failure_message(k.code()));
            }
        }
    }
}
