//! レジストリクライアントの TLS 部品: CPU 機能の事前確認・暗号 provider・OS ルート証明書（TASK-51.1・OCI-1）。
//!
//! `registry` モジュールの `RegistryClient::new` が呼ぶ。暗号実装は rustls-graviola（純 Rust）に固定し、
//! 差し替え点をこのモジュールの `crypto_provider` 1 か所に集める（#399 の残るリスクへの対応）。
//!
//! - graviola は暗号処理の入口で CPU 機能を `assert!` で確かめ、足りないと最初のハンドシェイクで panic する。
//!   そのため provider を作る前に同等以上の機能を確認し、不足なら `Unimplemented` で fail-closed にする
//! - `CryptoProvider::install_default` は使わない（プロセス全体への副作用を避け、Agent ごとに渡す）
//! - ルート証明書は OS のストア（`SSL_CERT_FILE` / `SSL_CERT_DIR` に従う）から読む。0 件は fail-closed
//!   （ureq は既定の webpki-roots 無しだと panic するため、必ず明示する）

use crate::error::{OciError, OciErrorCode};
use rustls::crypto::CryptoProvider;
use rustls_native_certs::CertificateResult;
use std::sync::Arc;
use ureq::tls::Certificate;

/// 読み込むルート証明書の最大件数（無制限確保の防止）。
pub(crate) const ROOT_CERTS_MAX: usize = 4096;

/// x86_64 で要求する CPU 機能（graviola の要件の上位集合。bmi2 は #399 の判断資料に合わせ追加）。
#[cfg(target_arch = "x86_64")]
const REQUIRED_FEATURES: &[&str] = &["aes", "pclmulqdq", "bmi1", "bmi2", "adx", "avx", "avx2"];
/// aarch64 で要求する CPU 機能。
#[cfg(target_arch = "aarch64")]
const REQUIRED_FEATURES: &[&str] = &["neon", "aes", "pmull", "sha2"];
/// 対応外のアーキテクチャでは要求を満たせないものとして扱う。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const REQUIRED_FEATURES: &[&str] = &["supported-architecture"];

/// 実 CPU に対する機能検出（std の safe なマクロ）。
#[cfg(target_arch = "x86_64")]
fn detect_cpu_feature(name: &str) -> bool {
    match name {
        "aes" => std::arch::is_x86_feature_detected!("aes"),
        "pclmulqdq" => std::arch::is_x86_feature_detected!("pclmulqdq"),
        "bmi1" => std::arch::is_x86_feature_detected!("bmi1"),
        "bmi2" => std::arch::is_x86_feature_detected!("bmi2"),
        "adx" => std::arch::is_x86_feature_detected!("adx"),
        "avx" => std::arch::is_x86_feature_detected!("avx"),
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        _ => false,
    }
}

/// 実 CPU に対する機能検出（std の safe なマクロ）。
#[cfg(target_arch = "aarch64")]
fn detect_cpu_feature(name: &str) -> bool {
    match name {
        "neon" => std::arch::is_aarch64_feature_detected!("neon"),
        "aes" => std::arch::is_aarch64_feature_detected!("aes"),
        "pmull" => std::arch::is_aarch64_feature_detected!("pmull"),
        "sha2" => std::arch::is_aarch64_feature_detected!("sha2"),
        _ => false,
    }
}

/// 対応外のアーキテクチャでは常に不足として扱う。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_cpu_feature(_name: &str) -> bool {
    false
}

/// `required` の各機能を `detect` で確かめ、不足があれば `Unimplemented`（不足名の一覧つき）を返す。
///
/// テストで偽の検出関数を渡せるよう、実 CPU の検出と分けてある。
pub(crate) fn check_features(
    detect: impl Fn(&str) -> bool,
    required: &[&str],
) -> Result<(), OciError> {
    let missing: Vec<&str> = required.iter().copied().filter(|f| !detect(f)).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(OciError::new(
            OciErrorCode::Unimplemented,
            format!("required CPU features are missing: {}", missing.join(", ")),
        ))
    }
}

/// 実 CPU が graviola の要件を満たすか確かめる（panic しない）。
pub(crate) fn probe_cpu() -> Result<(), OciError> {
    check_features(detect_cpu_feature, REQUIRED_FEATURES)
}

/// CPU 機能を確認したうえで graviola の暗号 provider を作る。
pub(crate) fn crypto_provider(
    cpu_check: impl FnOnce() -> Result<(), OciError>,
) -> Result<Arc<CryptoProvider>, OciError> {
    cpu_check()?;
    Ok(Arc::new(rustls_graviola::default_provider()))
}

/// OS のストアから読んだ結果を ureq 用のルート証明書へ変換する。
///
/// 0 件は `FailedPrecondition`、[`ROOT_CERTS_MAX`] 超過は `ResourceExhausted`。1 件以上読めていれば、
/// 読めなかった項目（`errors`）があっても続行する: OS のストアに壊れた項目が混じるのは一般的で、
/// 検証自体は rustls が証明書チェーン単位で行う。`errors` は件数のみ message に載せる。
pub(crate) fn load_roots(
    loader: impl FnOnce() -> CertificateResult,
) -> Result<Vec<Certificate<'static>>, OciError> {
    let result = loader();
    if result.certs.is_empty() {
        return Err(OciError::new(
            OciErrorCode::FailedPrecondition,
            format!(
                "no root certificates found in the OS trust store ({} load errors)",
                result.errors.len()
            ),
        ));
    }
    if result.certs.len() > ROOT_CERTS_MAX {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "too many root certificates in the OS trust store",
        ));
    }
    Ok(result
        .certs
        .iter()
        .map(|c| Certificate::from_der(c.as_ref()).to_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_native_certs::CertificateResult;

    fn result_with(n: usize, errors: usize) -> CertificateResult {
        let mut r = CertificateResult::default();
        for _ in 0..n {
            r.certs
                .push(rustls::pki_types::CertificateDer::from(vec![0x30, 0x00]));
        }
        for _ in 0..errors {
            r.errors.push(rustls_native_certs::Error {
                context: "test",
                kind: rustls_native_certs::ErrorKind::Io {
                    inner: std::io::Error::other("x"),
                    path: std::path::PathBuf::from("x"),
                },
            });
        }
        r
    }

    /// OCI-1: 機能が全て揃えば Ok、avx2 のみ欠ければ Unimplemented で名前を含む。
    #[test]
    fn check_features_reports_missing() {
        let req = ["aes", "avx2"];
        assert!(check_features(|_| true, &req).is_ok());
        let e = check_features(|f| f != "avx2", &req).expect_err("missing");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert_eq!(e.message(), "required CPU features are missing: avx2");
    }

    /// OCI-1・ERR-1: 実 CPU の確認は panic せず Ok か Unimplemented のどちらかを返す。
    #[test]
    fn probe_cpu_does_not_panic() {
        match probe_cpu() {
            Ok(()) => {}
            Err(e) => assert_eq!(e.code(), OciErrorCode::Unimplemented),
        }
    }

    /// OCI-1・ERR-1: CPU 確認が失敗すれば provider を作らず同じエラーを返す。
    #[test]
    fn crypto_provider_fails_closed() {
        let e = crypto_provider(|| Err(OciError::new(OciErrorCode::Unimplemented, "no")))
            .expect_err("fail");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
    }

    /// OCI-1・ERR-1: ルート証明書: 0 件は FailedPrecondition、一部エラーつきでも 1 件以上なら Ok、上限超過は ResourceExhausted。
    #[test]
    fn load_roots_cases() {
        let e = load_roots(|| result_with(0, 2)).expect_err("empty");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "no root certificates found in the OS trust store (2 load errors)"
        );
        assert_eq!(load_roots(|| result_with(3, 1)).expect("ok").len(), 3);
        let e = load_roots(|| result_with(ROOT_CERTS_MAX + 1, 0)).expect_err("many");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }
}
