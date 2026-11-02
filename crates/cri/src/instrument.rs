//! CRI 操作の計装連携点（REPAIR-4・ERR-3・TASK-57.1・#429）。
//!
//! `crate::runtime_service::CriRuntimeService` の RPC が、1 回の操作ごとの結果（成功 / 失敗と
//! gRPC ステータスコード）と所要時間を記録先へ渡すための境界。集計（成功・失敗件数とレイテンシ分布）と
//! 構造化ログへの出力は core の `OpRecorder` が担うが、cri は core へ依存しない（PLUG-1・CRI-7・CRI-8）
//! ため、本モジュールが cri 内の型だけで完結するトレイトを定義する（`fandhe-container-net`・
//! `fandhe-container-io` の `instrument` モジュールと同じ形）。core の記録器への接続は、core と cri の
//! 両方に依存し CRI の RPC を本番で呼ぶ crate（`fandhe-container-plugin-cri`。TASK-108）に置く newtype アダプタが担い
//! （`docs/architecture.md` の「計装アダプタの配置」の原則）、
//! `sample.kind().as_str()` を core の `OpName::new` へ、`sample.outcome()` / `sample.latency()` を
//! `OpRecorder::record` へ写す。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - core の `OpRecorder` との接続: 本番経路は plugin-cri の `CoreCriRecorder` を注入済み（TASK-108）。
//!   記録先を注入しないコンストラクタの既定は [`NoopCriOpRecorder`] で、何も出力されない
//! - `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・`PodSandboxStatus`・`ListPodSandbox`・`CreateContainer`・`StartContainer`・`StopContainer`・`RemoveContainer`・`ListContainers`・`ContainerStatus`・`Status`・`Version`・`UpdateRuntimeConfig`・`ListImages`・`ImageStatus`・`PullImage`・`RecordStoreLoad` 以外の RPC の種別は、RPC の実装（TASK-58.4 以降・TASK-61.3 以降）と一緒に [`CriOpKind`] へ追加する
//!
//! # 機微情報
//!
//! [`CriOpSample`] は種別・結果・ステータスコード・レイテンシと、レジストリの HTTP 状態の区分
//! （[`RegistryHttpClass`]。固定語彙の列挙で、生の HTTP 状態・URL・資格情報は持たない。#2966）のみを持つ。要求の中身（`config`・labels・
//! annotations・サンドボックス ID）とエラー文言は持たせない（`.claude/rules/security.md`）。

use std::time::{Duration, Instant};

use tonic::{Code, Status};

use crate::error::registry_http_status_from_metadata;

/// 計装対象の CRI 操作の種別（REPAIR-4）。
///
/// [`CriOpKind::as_str`] は core の `OpName` 規則（`[A-Za-z0-9._-]`・64 バイト以下）に収まる
/// 固定文字列を返す契約を持つ。cri は core の定数を import できないため規則を重複して持ち、
/// テストで固定する。閉じた enum なので自由入力の文字列がログのキーに入る経路はない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CriOpKind {
    /// `RuntimeService.RunPodSandbox` 1 回（入力検証から登録まで。CRI-1・TASK-57.1）。
    RunPodSandbox,
    /// `RuntimeService.StopPodSandbox` 1 回（ready から notready への遷移。CRI-1・TASK-57.2）。
    StopPodSandbox,
    /// `RuntimeService.RemovePodSandbox` 1 回（レジストリからの除去。CRI-1・TASK-57.2）。
    RemovePodSandbox,
    /// `RuntimeService.PodSandboxStatus` 1 回（レジストリの読み取り。CRI-1・TASK-57.3）。
    PodSandboxStatus,
    /// `RuntimeService.ListPodSandbox` 1 回（レジストリの絞り込み一覧。CRI-1・TASK-57.3）。
    ListPodSandbox,
    /// `RuntimeService.CreateContainer` 1 回（入力検証からレジストリ登録まで。CRI-1・TASK-58.1）。
    CreateContainer,
    /// `RuntimeService.StartContainer` 1 回（created から running への遷移。CRI-1・TASK-58.1）。
    StartContainer,
    /// `RuntimeService.StopContainer` 1 回（running から exited への遷移。CRI-1・TASK-58.2）。
    StopContainer,
    /// `RuntimeService.RemoveContainer` 1 回（記録の除去と枠の解放。CRI-1・TASK-58.2）。
    RemoveContainer,
    /// `RuntimeService.ListContainers` 1 回（読み取り専用の一覧。CRI-1・TASK-58.3）。
    ListContainers,
    /// `RuntimeService.ContainerStatus` 1 回（読み取り専用の状態照会。CRI-1・TASK-58.3）。
    ContainerStatus,
    /// `RuntimeService.Status` 1 回（待ちのない準備状態の報告。CRI-1・CRI-2・#2830）。
    Status,
    /// `RuntimeService.Version` 1 回（定数の応答。CRI-1・#2896）。
    Version,
    /// `RuntimeService.UpdateRuntimeConfig` 1 回（pod CIDR の検証と記録。CRI-1・CRI-2・#2896）。
    UpdateRuntimeConfig,
    /// `ImageService.ListImages` 1 回（ローカルキャッシュの絞り込み一覧。CRI-4・TASK-61.1）。
    ListImages,
    /// `ImageService.ImageStatus` 1 回（ローカルキャッシュの単一参照解決。CRI-4・TASK-61.2）。
    ImageStatus,
    /// `ImageService.PullImage` 1 回（レジストリからのイメージ取り込み。CRI-4・OCI-1・TASK-61.3）。
    PullImage,
    /// 起動時の記録の再採用の 1 件（記録ストアからの読み込みと復号。CRI-2・REPAIR-4・#2935）。
    RecordStoreLoad,
    /// shim v2 の ttrpc 要求の dispatch 1 回（サービス呼び出しの結果。CRI-5・TASK-62.1・MS-7・REPAIR-4）。
    ShimV2Dispatch,
    /// shim v2 の ttrpc の不正フレーム・不正な要求の拒否 1 回（CRI-5・TASK-62.1・MS-7・REPAIR-4）。
    ShimV2Frame,
    /// shim v2 の ttrpc の読み書き失敗・期限切れ 1 回（CRI-5・TASK-62.1・MS-7・REPAIR-4・REPAIR-5）。
    ShimV2Io,
    /// shim v2 起動バイナリの `start` 1 回（socket の用意からデーモンの準備完了まで。CRI-5・TASK-62.7.1・REPAIR-4）。
    ShimV2Start,
    /// shim v2 起動バイナリの `delete` 1 回（socket の片付け。CRI-5・TASK-62.7.1・REPAIR-4）。
    ShimV2Delete,
}

impl CriOpKind {
    /// core の `OpName` へ渡す安定した操作名。
    pub fn as_str(self) -> &'static str {
        match self {
            CriOpKind::RunPodSandbox => "cri.run_pod_sandbox",
            CriOpKind::StopPodSandbox => "cri.stop_pod_sandbox",
            CriOpKind::RemovePodSandbox => "cri.remove_pod_sandbox",
            CriOpKind::PodSandboxStatus => "cri.pod_sandbox_status",
            CriOpKind::ListPodSandbox => "cri.list_pod_sandbox",
            CriOpKind::CreateContainer => "cri.create_container",
            CriOpKind::StartContainer => "cri.start_container",
            CriOpKind::StopContainer => "cri.stop_container",
            CriOpKind::RemoveContainer => "cri.remove_container",
            CriOpKind::ListContainers => "cri.list_containers",
            CriOpKind::ContainerStatus => "cri.container_status",
            CriOpKind::Status => "cri.status",
            CriOpKind::Version => "cri.version",
            CriOpKind::UpdateRuntimeConfig => "cri.update_runtime_config",
            CriOpKind::ListImages => "cri.list_images",
            CriOpKind::ImageStatus => "cri.image_status",
            CriOpKind::PullImage => "cri.pull_image",
            CriOpKind::RecordStoreLoad => "cri.record_store_load",
            CriOpKind::ShimV2Dispatch => "cri.shim_v2.dispatch",
            CriOpKind::ShimV2Frame => "cri.shim_v2.frame",
            CriOpKind::ShimV2Io => "cri.shim_v2.io",
            CriOpKind::ShimV2Start => "cri.shim_v2.start",
            CriOpKind::ShimV2Delete => "cri.shim_v2.delete",
        }
    }
}

/// 操作の結果区分（真偽値ではなく将来拡張できる型。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CriOpOutcome {
    /// 成功（ステータスコードが `OK`）。
    Success,
    /// 失敗（入力不正・上限超過・内部エラー・早期 return・panic を含む）。
    Failure,
}

impl CriOpOutcome {
    /// ステータスコードから結果区分を導く（`OK` だけが成功）。
    pub fn from_code(code: Code) -> Self {
        match code {
            Code::Ok => CriOpOutcome::Success,
            _ => CriOpOutcome::Failure,
        }
    }

    /// 構造化ログの値に使う安定した名前。
    pub fn as_str(self) -> &'static str {
        match self {
            CriOpOutcome::Success => "success",
            CriOpOutcome::Failure => "failure",
        }
    }
}

/// gRPC ステータスコードの正準名（ERR-3 の `INVALID_ARGUMENT` 等。構造化ログの値に使う固定文字列）。
pub fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// レジストリの HTTP 状態の区分（固定の語彙。#2966・REPAIR-4・CRI-3・OCI-1）。
///
/// gRPC では 401/403 がどちらも `PERMISSION_DENIED`、429 と 5xx がどちらも `UNAVAILABLE` に潰れるため、
/// 記録でそれらを見分ける目的で持つ。生の値は持たず、plugin-cri が
/// [`op_name`](Self::op_name) を oci 専用の記録器へ失敗として記録する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistryHttpClass {
    /// 401。
    Unauthorized,
    /// 403。
    Forbidden,
    /// 404。
    NotFound,
    /// 408。
    RequestTimeout,
    /// 429（rate limit）。
    RateLimited,
    /// 上記以外の 400..=499。
    OtherClientError,
    /// 500..=599。
    ServerError,
    /// 100..=399。
    Other,
}

impl RegistryHttpClass {
    /// 全区分（宣言順）。
    pub const ALL: [RegistryHttpClass; 8] = [
        Self::Unauthorized,
        Self::Forbidden,
        Self::NotFound,
        Self::RequestTimeout,
        Self::RateLimited,
        Self::OtherClientError,
        Self::ServerError,
        Self::Other,
    ];

    /// HTTP 状態から区分を導く。100..=599 の外は `None`（数えない。fail-closed）。
    pub fn from_http_status(status: u16) -> Option<Self> {
        match status {
            401 => Some(Self::Unauthorized),
            403 => Some(Self::Forbidden),
            404 => Some(Self::NotFound),
            408 => Some(Self::RequestTimeout),
            429 => Some(Self::RateLimited),
            400..=499 => Some(Self::OtherClientError),
            500..=599 => Some(Self::ServerError),
            100..=399 => Some(Self::Other),
            _ => None,
        }
    }

    /// 区分の固定の接尾辞（`[a-z_]`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RequestTimeout => "request_timeout",
            Self::RateLimited => "rate_limited",
            Self::OtherClientError => "client_error",
            Self::ServerError => "server_error",
            Self::Other => "other",
        }
    }

    /// 記録器へ渡す完全な操作名（core の `OpName` 規則 `[A-Za-z0-9._-]`・64 バイト以下に収まる固定文字列）。
    pub fn op_name(self) -> &'static str {
        match self {
            Self::Unauthorized => "cri.pull_image.registry_http.unauthorized",
            Self::Forbidden => "cri.pull_image.registry_http.forbidden",
            Self::NotFound => "cri.pull_image.registry_http.not_found",
            Self::RequestTimeout => "cri.pull_image.registry_http.request_timeout",
            Self::RateLimited => "cri.pull_image.registry_http.rate_limited",
            Self::OtherClientError => "cri.pull_image.registry_http.client_error",
            Self::ServerError => "cri.pull_image.registry_http.server_error",
            Self::Other => "cri.pull_image.registry_http.other",
        }
    }
}

/// 1 回の操作の計測結果（固定サイズの値型。ヒープ確保なし）。
///
/// 結果区分はステータスコードから導くため、「成功なのにエラーコード」のような食い違った値は作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CriOpSample {
    kind: CriOpKind,
    code: Code,
    latency: Duration,
    registry_http: Option<RegistryHttpClass>,
}

impl CriOpSample {
    /// サンプルを作る。
    pub fn new(kind: CriOpKind, code: Code, latency: Duration) -> Self {
        Self {
            kind,
            code,
            latency,
            registry_http: None,
        }
    }

    /// レジストリの HTTP 状態の区分を付ける（#2966）。
    pub fn with_registry_http(mut self, class: RegistryHttpClass) -> Self {
        self.registry_http = Some(class);
        self
    }

    /// レジストリの HTTP 状態の区分。レジストリ由来の失敗（`PullImage`）以外は `None`。
    pub fn registry_http(&self) -> Option<RegistryHttpClass> {
        self.registry_http
    }

    /// 操作の種別。
    pub fn kind(&self) -> CriOpKind {
        self.kind
    }

    /// 操作の結果区分（ステータスコードから導く）。
    pub fn outcome(&self) -> CriOpOutcome {
        CriOpOutcome::from_code(self.code)
    }

    /// 呼び出し元へ返した gRPC ステータスコード（成功は `Code::Ok`）。失敗の内訳の集計に使う。
    pub fn code(&self) -> Code {
        self.code
    }

    /// 操作に要した時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// cri の計測結果を受け取る記録先（REPAIR-4）。
///
/// 契約: RPC の応答経路から呼ばれるため、有界時間で戻ること（相手応答待ち・無期限の
/// ロック待ちをしない。O(1) の短い有界ロックは許容。REPAIR-5）。panic しないこと。
/// 戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えないため。
/// `dyn CriOpRecorder` として `Arc` 共有できる。サービス側は内部状態のロックを解放してから呼ぶ。
pub trait CriOpRecorder: Send + Sync {
    /// 1 件の計測結果を記録する。
    fn record_cri_op(&self, sample: &CriOpSample);
}

/// 計測しない場合に明示的に渡す既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCriOpRecorder;

impl CriOpRecorder for NoopCriOpRecorder {
    fn record_cri_op(&self, _sample: &CriOpSample) {}
}

/// 計測中の操作を表すガード。
///
/// [`finish_with`](Self::finish_with) で結果を確定する。未確定のまま Drop された場合
/// （早期 return・`?`・panic の巻き戻し）は `Code::Internal` の失敗として記録する（fail-closed）。
#[must_use = "drop without finishing records a failure"]
pub struct CriOpTimer<'a> {
    recorder: &'a dyn CriOpRecorder,
    kind: CriOpKind,
    started: Instant,
    done: bool,
}

impl<'a> CriOpTimer<'a> {
    /// 計測を開始する。
    pub fn start(recorder: &'a dyn CriOpRecorder, kind: CriOpKind) -> Self {
        Self {
            recorder,
            kind,
            started: Instant::now(),
            done: false,
        }
    }

    fn emit(&mut self, code: Code, registry_http: Option<RegistryHttpClass>) {
        if self.done {
            return;
        }
        self.done = true;
        let mut sample = CriOpSample::new(self.kind, code, self.started.elapsed());
        if let Some(class) = registry_http {
            sample = sample.with_registry_http(class);
        }
        self.recorder.record_cri_op(&sample);
    }

    /// RPC の結果に応じて確定する（`Ok` は `Code::Ok`、`Err` はその `Status` のコード。文言は読まない）。
    pub fn finish_with<T>(mut self, result: &Result<T, Status>) {
        let (code, class) = match result {
            Ok(_) => (Code::Ok, None),
            // メタデータを付けるのは `PullError::from_oci` 経由だけで、他の RPC では常に `None`（#2966）。
            Err(status) => (
                status.code(),
                registry_http_status_from_metadata(status.metadata())
                    .and_then(RegistryHttpClass::from_http_status),
            ),
        };
        self.emit(code, class);
    }
}

impl Drop for CriOpTimer<'_> {
    fn drop(&mut self) {
        self.emit(Code::Internal, None);
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! 記録内容を照合するための試験用記録先。
    use super::*;
    use std::sync::Mutex;

    /// 受け取ったサンプルを順に保持する。
    #[derive(Default)]
    pub(crate) struct Collect(Mutex<Vec<CriOpSample>>);

    impl CriOpRecorder for Collect {
        fn record_cri_op(&self, s: &CriOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*s);
            }
        }
    }

    impl Collect {
        /// これまでに記録されたサンプル。
        pub(crate) fn items(&self) -> Vec<CriOpSample> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }

        /// (種別, 結果, ステータスコード) の列。
        pub(crate) fn outcomes(&self) -> Vec<(CriOpKind, CriOpOutcome, Code)> {
            self.items()
                .iter()
                .map(|s| (s.kind(), s.outcome(), s.code()))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Collect;
    use super::*;
    use std::sync::Arc;

    const ALL_KINDS: [CriOpKind; 20] = [
        CriOpKind::RunPodSandbox,
        CriOpKind::StopPodSandbox,
        CriOpKind::RemovePodSandbox,
        CriOpKind::PodSandboxStatus,
        CriOpKind::ListPodSandbox,
        CriOpKind::CreateContainer,
        CriOpKind::StartContainer,
        CriOpKind::StopContainer,
        CriOpKind::RemoveContainer,
        CriOpKind::ListContainers,
        CriOpKind::ContainerStatus,
        CriOpKind::Status,
        CriOpKind::Version,
        CriOpKind::UpdateRuntimeConfig,
        CriOpKind::ListImages,
        CriOpKind::ImageStatus,
        CriOpKind::PullImage,
        CriOpKind::RecordStoreLoad,
        CriOpKind::ShimV2Start,
        CriOpKind::ShimV2Delete,
    ];

    /// REPAIR-4・CRI-3（#2966）: HTTP 状態から区分への写像（境界値）と語彙の健全性。
    #[test]
    fn repair4_registry_http_class_table() {
        use RegistryHttpClass as C;
        for (status, expected) in [
            (99, None),
            (100, Some(C::Other)),
            (399, Some(C::Other)),
            (400, Some(C::OtherClientError)),
            (401, Some(C::Unauthorized)),
            (403, Some(C::Forbidden)),
            (404, Some(C::NotFound)),
            (408, Some(C::RequestTimeout)),
            (429, Some(C::RateLimited)),
            (499, Some(C::OtherClientError)),
            (500, Some(C::ServerError)),
            (599, Some(C::ServerError)),
            (600, None),
        ] {
            assert_eq!(C::from_http_status(status), expected, "status={status}");
        }
        let mut names = std::collections::HashSet::new();
        for c in C::ALL {
            let name = c.op_name();
            assert!(names.insert(name), "duplicate {name}");
            assert!(name.len() <= 64);
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            );
            assert_eq!(name, format!("cri.pull_image.registry_http.{}", c.as_str()));
        }
        assert_eq!(names.len(), 8);
    }

    /// REPAIR-4・CRI-3（#2966）: timer は失敗の Status のメタデータから区分を導く。
    #[test]
    fn repair4_timer_records_registry_http_class() {
        use tonic::metadata::{MetadataMap, MetadataValue};
        let with = |http: u16| {
            let mut md = MetadataMap::new();
            md.insert(
                crate::error::REGISTRY_HTTP_STATUS_METADATA_KEY,
                MetadataValue::from(http),
            );
            Status::with_metadata(Code::Unavailable, "x", md)
        };
        let run = |r: Result<(), Status>| {
            let rec = Collect::default();
            CriOpTimer::start(&rec, CriOpKind::PullImage).finish_with(&r);
            rec.items()[0].registry_http()
        };
        assert_eq!(run(Err(with(429))), Some(RegistryHttpClass::RateLimited));
        assert_eq!(run(Err(with(503))), Some(RegistryHttpClass::ServerError));
        assert_eq!(run(Err(Status::unavailable("x"))), None);
        assert_eq!(run(Ok(())), None);
        let rec = Collect::default();
        drop(CriOpTimer::start(&rec, CriOpKind::PullImage));
        assert_eq!(rec.items()[0].registry_http(), None);
    }

    /// REPAIR-4: 操作名は安定した固定文字列。
    #[test]
    fn repair4_cri_op_kind_as_str_is_stable() {
        assert_eq!(CriOpKind::RunPodSandbox.as_str(), "cri.run_pod_sandbox");
        assert_eq!(CriOpKind::StopPodSandbox.as_str(), "cri.stop_pod_sandbox");
        assert_eq!(
            CriOpKind::RemovePodSandbox.as_str(),
            "cri.remove_pod_sandbox"
        );
        assert_eq!(
            CriOpKind::PodSandboxStatus.as_str(),
            "cri.pod_sandbox_status"
        );
        assert_eq!(CriOpKind::ListPodSandbox.as_str(), "cri.list_pod_sandbox");
        assert_eq!(CriOpKind::CreateContainer.as_str(), "cri.create_container");
        assert_eq!(CriOpKind::StartContainer.as_str(), "cri.start_container");
        assert_eq!(CriOpKind::StopContainer.as_str(), "cri.stop_container");
        assert_eq!(CriOpKind::RemoveContainer.as_str(), "cri.remove_container");
        assert_eq!(CriOpKind::ListContainers.as_str(), "cri.list_containers");
        assert_eq!(CriOpKind::ContainerStatus.as_str(), "cri.container_status");
        assert_eq!(CriOpKind::Status.as_str(), "cri.status");
        assert_eq!(CriOpKind::Version.as_str(), "cri.version");
        assert_eq!(
            CriOpKind::UpdateRuntimeConfig.as_str(),
            "cri.update_runtime_config"
        );
        assert_eq!(CriOpKind::ListImages.as_str(), "cri.list_images");
        assert_eq!(CriOpKind::ImageStatus.as_str(), "cri.image_status");
        assert_eq!(CriOpKind::PullImage.as_str(), "cri.pull_image");
    }

    /// REPAIR-4: 操作名は core の `OpName::new` と同じ規則に収まる（cri は core に依存できないため
    /// 重複して固定する）。
    #[test]
    fn repair4_cri_op_kind_names_fit_core_op_name_contract() {
        for kind in ALL_KINDS {
            let s = kind.as_str();
            assert!(!s.is_empty() && s.len() <= 64);
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            );
        }
    }

    /// REPAIR-4・ERR-3: 結果区分はステータスコードから導かれ、`OK` だけが成功になる。
    #[test]
    fn repair4_outcome_is_derived_from_code() {
        assert_eq!(CriOpOutcome::from_code(Code::Ok), CriOpOutcome::Success);
        for code in [
            Code::InvalidArgument,
            Code::FailedPrecondition,
            Code::Internal,
            Code::Unimplemented,
        ] {
            assert_eq!(CriOpOutcome::from_code(code), CriOpOutcome::Failure);
        }
        assert_eq!(CriOpOutcome::Success.as_str(), "success");
        assert_eq!(CriOpOutcome::Failure.as_str(), "failure");
    }

    /// ERR-3: ステータスコードの正準名は gRPC の名前と一致する。
    #[test]
    fn err3_code_names_are_canonical() {
        assert_eq!(code_name(Code::Ok), "OK");
        assert_eq!(code_name(Code::InvalidArgument), "INVALID_ARGUMENT");
        assert_eq!(code_name(Code::FailedPrecondition), "FAILED_PRECONDITION");
        assert_eq!(code_name(Code::ResourceExhausted), "RESOURCE_EXHAUSTED");
        assert_eq!(code_name(Code::Unimplemented), "UNIMPLEMENTED");
        assert_eq!(code_name(Code::Internal), "INTERNAL");
        assert_eq!(code_name(Code::NotFound), "NOT_FOUND");
    }

    /// REPAIR-4: 成功と失敗が、それぞれのステータスコードつきで 1 件ずつ記録される。
    #[test]
    fn repair4_timer_records_code_of_result() {
        let c = Collect::default();
        let ok: Result<u32, Status> = Ok(7);
        CriOpTimer::start(&c, CriOpKind::RunPodSandbox).finish_with(&ok);
        let err: Result<u32, Status> = Err(Status::invalid_argument("secret-like text"));
        CriOpTimer::start(&c, CriOpKind::RunPodSandbox).finish_with(&err);
        assert_eq!(
            c.outcomes(),
            vec![
                (CriOpKind::RunPodSandbox, CriOpOutcome::Success, Code::Ok),
                (
                    CriOpKind::RunPodSandbox,
                    CriOpOutcome::Failure,
                    Code::InvalidArgument
                ),
            ]
        );
    }

    /// REPAIR-4: レイテンシは操作に要した実時間を含む。
    #[test]
    fn repair4_timer_measures_latency() {
        let c = Collect::default();
        let timer = CriOpTimer::start(&c, CriOpKind::RunPodSandbox);
        std::thread::sleep(Duration::from_millis(20));
        timer.finish_with(&Ok::<(), Status>(()));
        let items = c.items();
        assert_eq!(items.len(), 1);
        let latency = items.first().map(CriOpSample::latency).expect("one sample");
        assert!(latency >= Duration::from_millis(20));
        assert!(latency < Duration::from_secs(5));
    }

    /// REPAIR-4: 未確定のまま Drop されたガードは `Internal` の失敗を 1 件記録する（fail-closed）。
    #[test]
    fn repair4_timer_drop_records_internal_failure() {
        let c = Collect::default();
        {
            let _t = CriOpTimer::start(&c, CriOpKind::RunPodSandbox);
        }
        assert_eq!(
            c.outcomes(),
            vec![(
                CriOpKind::RunPodSandbox,
                CriOpOutcome::Failure,
                Code::Internal
            )]
        );
    }

    /// REPAIR-4: panic で巻き戻っても失敗が 1 件だけ記録される。
    #[test]
    fn repair4_timer_records_failure_on_panic() {
        let c = Collect::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _t = CriOpTimer::start(&c, CriOpKind::RunPodSandbox);
            panic!("boom");
        }));
        assert!(r.is_err());
        assert_eq!(
            c.outcomes(),
            vec![(
                CriOpKind::RunPodSandbox,
                CriOpOutcome::Failure,
                Code::Internal
            )]
        );
    }

    /// REPAIR-4: 記録先は `Arc<dyn CriOpRecorder>` として共有でき、Send + Sync。
    #[test]
    fn repair4_cri_op_recorder_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NoopCriOpRecorder>();
        assert_send_sync::<dyn CriOpRecorder>();
        let r: Arc<dyn CriOpRecorder> = Arc::new(NoopCriOpRecorder);
        let sample = CriOpSample::new(
            CriOpKind::RunPodSandbox,
            Code::FailedPrecondition,
            Duration::from_millis(3),
        );
        r.record_cri_op(&sample);
        assert_eq!(sample.kind(), CriOpKind::RunPodSandbox);
        assert_eq!(sample.outcome(), CriOpOutcome::Failure);
        assert_eq!(sample.code(), Code::FailedPrecondition);
        assert_eq!(sample.latency(), Duration::from_millis(3));
    }
}
