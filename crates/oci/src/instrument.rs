//! oci 操作の計装連携点（REPAIR-4・OCI-1・TASK-51.2・MS-4・#401）。
//!
//! oci の各操作（認証・manifest / blob 取得・検証・解凍・展開・在庫の操作・回収）が、1 回の操作ごとの結果
//! （成功 / 失敗とエラー code）と所要時間を記録先へ渡すための境界。集計と構造化ログへの出力は、`docs/architecture.md` の「計装アダプタの配置」の原則に従い、
//! oci の操作を本番で呼び `OpRecorder` を持つ crate が `OciOpRecorder` を実装して差し込む（`fandhe-container-net` の `instrument` と同じ形。oci は core に依存しない）。
//! 本番の記録先は plugin-cri の `CoreOciRecorder`（`adapter.rs`）で、oci 専用の `OpRecorder` へ `OciOpKind::as_str` の
//! 名前で写す（エラー code は名前に含めない。写像と専用にした理由は `docs/design/pull-inventory-wiring.md`。#2900）。
//! CLI の `image ls` / `image rm` / `image tag` / `system df` の記録先は cli の `CliOciRecorder`（`commands/oci_recorder.rs`）で、
//! 同じ写像を `with_ops` の `OpRecorder` へ書く（#2968）。
//! 既定は何も記録しない `NoopOciOpRecorder`。
//!
//! # 機微情報
//!
//! `OciOpSample` は種別・結果・エラー code・レイテンシのみを持つ。トークン値・URL・
//! 非信頼ヘッダ値・エラー message は持たせない（`.claude/rules/security.md`）。

use crate::error::{OciError, OciErrorCode};
use std::fmt::Debug;
use std::time::{Duration, Instant};

/// 計装対象の oci 操作の種別。`as_str` は固定文字列（自由入力がログのキーに入る経路はない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OciOpKind {
    /// 匿名トークン取得（`/v2/` プローブからトークンエンドポイントまでの全体。TASK-51.2）。
    AuthenticateAnonymous,
    /// Basic 認証の検証（`/v2/` プローブと資格情報つき再要求の全体。TASK-54.1・OCI-3）。
    AuthenticateBasic,
    /// 資格情報つき Bearer トークン交換（`/v2/` プローブからトークンエンドポイントまでの全体。TASK-54.2・OCI-3）。
    AuthenticateBearer,
    /// チャレンジに応じた Basic / Bearer 自動選択の統一入口（プローブから認証確立までの全体。TASK-54.3・OCI-3）。
    Authenticate,
    /// マニフェスト取得（image index の場合は platform 解決後の取得まで。TASK-51.3）。
    FetchManifest,
    /// blob（レイヤー・config）のストリーミング取得（TASK-51.4）。
    FetchBlob,
    /// 取得済み blob の sha256 digest 検証（open 失敗を含む操作全体。TASK-52.1）。
    VerifyBlobDigest,
    /// レイヤー blob の gzip 展開（open 失敗を含む操作全体。TASK-52.2）。
    DecompressLayer,
    /// レイヤー tar のルート配下への展開（TASK-52.3）。
    ExtractLayer,
    /// `image ls` 相当の一覧集計（TASK-183.3・OCI-7）。
    ListImages,
    /// `system df` 相当の使用容量集計（TASK-183.3・OCI-7）。
    DiskUsage,
    /// `image rm` の実行（untag または完全削除。TASK-183.6・OCI-7）。
    RemoveImage,
    /// イメージストアの排他区間の取得（待機・Timeout・毒化・ロックファイル異常を含む。TASK-183.2・OCI-7）。
    AcquireImageStoreLock,
    /// pull セッションの開始とステージングディレクトリの作成（TASK-183.9・OCI-7）。
    BeginPull,
    /// pull による既存 blob のリース登録と実体確認（stat 失敗・重複取得を含む操作全体。TASK-183.9・OCI-7）。
    LeaseBlob,
    /// pull がリーストークンを返却して自分のリースを外す操作（他セッションのトークン拒否を含む。TASK-183.9・OCI-7）。
    ReleaseBlobLease,
    /// pull の公開（検証・ステージングからの移動・manifest とタグの登録・リース解放の全体。失敗時のロールバックは含まず `AbortPull` で別に記録する。TASK-183.10・OCI-7）。
    PublishPull,
    /// pull の中断・失敗時のロールバック（自分のリース解放とステージング削除。TASK-183.10・OCI-7）。
    AbortPull,
    /// `image prune` の実行（無参照イメージ・レイヤーの回収。TASK-183.7・OCI-7）。
    PruneImages,
    /// `image tag` のタグ登録（TASK-183.4・OCI-7）。
    TagImage,
    /// 削除ジャーナルが残っていたときの再試行（ロールフォワード。TASK-183.11.1・OCI-7・#851）。
    RecoverPendingDeletion,
    /// クラッシュで残った pull のリース・ステージングの回収 GC（走査・リース解放・削除の全体。一部の削除失敗は失敗として記録する。TASK-183.11.2・OCI-7・#852）。
    RecoverStalePulls,
}

impl OciOpKind {
    /// 安定した操作名。
    pub fn as_str(self) -> &'static str {
        match self {
            OciOpKind::AuthenticateAnonymous => "oci.auth.anonymous",
            OciOpKind::AuthenticateBasic => "oci.auth.basic",
            OciOpKind::AuthenticateBearer => "oci.auth.bearer",
            OciOpKind::Authenticate => "oci.auth",
            OciOpKind::FetchManifest => "oci.manifest.fetch",
            OciOpKind::FetchBlob => "oci.blob.fetch",
            OciOpKind::VerifyBlobDigest => "oci.blob.verify",
            OciOpKind::DecompressLayer => "oci.layer.decompress",
            OciOpKind::ExtractLayer => "oci.layer.extract",
            OciOpKind::ListImages => "oci.image.list",
            OciOpKind::DiskUsage => "oci.image.df",
            OciOpKind::RemoveImage => "oci.image.rm",
            OciOpKind::AcquireImageStoreLock => "oci.store.lock",
            OciOpKind::BeginPull => "oci.pull.begin",
            OciOpKind::LeaseBlob => "oci.pull.lease",
            OciOpKind::ReleaseBlobLease => "oci.pull.release",
            OciOpKind::PublishPull => "oci.pull.publish",
            OciOpKind::AbortPull => "oci.pull.abort",
            OciOpKind::PruneImages => "oci.image.prune",
            OciOpKind::TagImage => "oci.image.tag",
            OciOpKind::RecoverPendingDeletion => "oci.image.gc_recover",
            OciOpKind::RecoverStalePulls => "oci.pull.gc_recover",
        }
    }
}

/// 操作の結果区分（真偽値ではなく将来拡張できる型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OciOpOutcome {
    /// 成功。
    Success,
    /// 失敗。HTTP エラー・タイムアウト・解析失敗などの分類は `OciOpSample::error_code`。
    Failure,
}

/// 1 回の操作の計測結果（固定サイズの値型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciOpSample {
    kind: OciOpKind,
    outcome: OciOpOutcome,
    error_code: Option<OciErrorCode>,
    latency: Duration,
}

impl OciOpSample {
    /// サンプルを作る。
    pub fn new(
        kind: OciOpKind,
        outcome: OciOpOutcome,
        error_code: Option<OciErrorCode>,
        latency: Duration,
    ) -> Self {
        Self {
            kind,
            outcome,
            error_code,
            latency,
        }
    }

    /// 操作の種別。
    pub fn kind(&self) -> OciOpKind {
        self.kind
    }

    /// 操作の結果区分。
    pub fn outcome(&self) -> OciOpOutcome {
        self.outcome
    }

    /// 失敗時のエラー分類（成功時と、分類不能な巻き戻し時は `None`）。
    pub fn error_code(&self) -> Option<OciErrorCode> {
        self.error_code
    }

    /// 操作に要した時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// oci の計測結果を受け取る記録先。
///
/// 契約: 有界時間で戻ること（I/O・無期限のロック待ちをしない。REPAIR-5）。panic しないこと。
/// 戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えないため。
pub trait OciOpRecorder: Send + Sync + Debug {
    /// 1 件の計測結果を記録する。
    fn record_oci_op(&self, sample: &OciOpSample);
}

/// 計測しない既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopOciOpRecorder;

impl OciOpRecorder for NoopOciOpRecorder {
    fn record_oci_op(&self, _sample: &OciOpSample) {}
}

/// クロージャを計測して結果をそのまま返す。panic で巻き戻された場合も `Failure` を 1 件記録する。
pub(crate) fn record_oci_op<T>(
    recorder: &dyn OciOpRecorder,
    kind: OciOpKind,
    f: impl FnOnce() -> Result<T, OciError>,
) -> Result<T, OciError> {
    struct Guard<'a> {
        recorder: &'a dyn OciOpRecorder,
        kind: OciOpKind,
        started: Instant,
        done: bool,
    }
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            if !self.done {
                let s = OciOpSample::new(
                    self.kind,
                    OciOpOutcome::Failure,
                    None,
                    self.started.elapsed(),
                );
                self.recorder.record_oci_op(&s);
            }
        }
    }
    let mut guard = Guard {
        recorder,
        kind,
        started: Instant::now(),
        done: false,
    };
    let result = f();
    guard.done = true;
    let (outcome, code) = match &result {
        Ok(_) => (OciOpOutcome::Success, None),
        Err(e) => (OciOpOutcome::Failure, Some(e.code())),
    };
    recorder.record_oci_op(&OciOpSample::new(
        kind,
        outcome,
        code,
        guard.started.elapsed(),
    ));
    result
}

#[cfg(test)]
pub(crate) mod testing {
    //! 記録内容を照合するための試験用記録先。
    use super::*;
    use std::sync::Mutex;

    /// 受け取ったサンプルを順に保持する。
    #[derive(Debug, Default)]
    pub(crate) struct Collect(pub(crate) Mutex<Vec<OciOpSample>>);

    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &OciOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*s);
            }
        }
    }

    impl Collect {
        pub(crate) fn items(&self) -> Vec<OciOpSample> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Collect;
    use super::*;

    /// REPAIR-4: 成功は code なし、失敗は code つきで 1 件ずつ記録される。
    #[test]
    fn records_success_and_failure() {
        let c = Collect::default();
        let ok: Result<u8, OciError> =
            record_oci_op(&c, OciOpKind::AuthenticateAnonymous, || Ok(1));
        assert_eq!(ok.expect("ok"), 1);
        let err: Result<u8, OciError> = record_oci_op(&c, OciOpKind::AuthenticateAnonymous, || {
            Err(OciError::new(OciErrorCode::Timeout, "x"))
        });
        assert!(err.is_err());
        let items = c.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[0].error_code(), None);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::Timeout));
        assert_eq!(items[1].kind().as_str(), "oci.auth.anonymous");
        assert_eq!(OciOpKind::FetchManifest.as_str(), "oci.manifest.fetch");
        assert_eq!(OciOpKind::FetchBlob.as_str(), "oci.blob.fetch");
        assert_eq!(OciOpKind::TagImage.as_str(), "oci.image.tag");
        assert_eq!(OciOpKind::PublishPull.as_str(), "oci.pull.publish");
        assert_eq!(OciOpKind::AbortPull.as_str(), "oci.pull.abort");
    }

    /// REPAIR-4: panic で巻き戻されても Failure が 1 件残る。
    #[test]
    fn panic_records_failure() {
        let c = Collect::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<u8, OciError> =
                record_oci_op(&c, OciOpKind::AuthenticateAnonymous, || panic!("boom"));
        }));
        assert!(r.is_err());
        let items = c.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].outcome(), OciOpOutcome::Failure);
    }
}
