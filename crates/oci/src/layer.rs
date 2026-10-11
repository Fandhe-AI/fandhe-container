//! 取得済み blob の sha256 digest 検証（TASK-52.1・OCI-1・MS-4・#405）。
//!
//! `RegistryClient::fetch_blob`（TASK-51.4）が保存した blob はサイズ検証のみで、本文のハッシュは
//! descriptor の digest と未突合である。このモジュールはファイルを固定長バッファで読んで sha256 を計算し、
//! 参照 digest と完全一致しなければ `DataLoss` で拒否する（fail-closed。ソフトウェアとデータの完全性）。
//!
//! 呼び出し契約: layer 展開（TASK-52.x）やキャッシュ公開の前に、呼び出し側が本検証を通すこと。
//! 検証対象は呼び出し側が管理するステージング領域のファイルとし、パスはエラー文言に載せない。
//! 未実装（後続 issue）: `fetch_blob` 内への組み込み、manifest 本文の digest 突合、展開・キャッシュ格納。

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;
use crate::registry::FetchedBlob;

/// 読み込みバッファ長（メモリ使用量を入力サイズに依存させない）。
const HASH_BUF_LEN: usize = 64 * 1024;

/// digest 検証に成功した blob（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedBlob {
    /// 本文から計算し、参照 digest と一致を確認した digest。
    pub digest: Digest,
    /// 読み取ったバイト数。
    pub size: u64,
}

/// 書き手のいない FIFO 等で `open` が無期限に止まらないよう、Unix では非ブロッキングで開く（REPAIR-5）。
/// 通常ファイルの読み取りには影響しない。値は OS ごとの `O_NONBLOCK`（libc 依存を増やさないため定数で持つ）。
#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;

/// 種別確認前にブロックしない設定で blob ファイルを開く。
fn open_blob(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(O_NONBLOCK);
    }
    opts.open(path)
}

/// 計装なしの `verify_blob_digest_with`（`NoopOciOpRecorder`）。
pub fn verify_blob_digest(
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest_with(&NoopOciOpRecorder, path, expected, max_bytes)
}

/// 検証全体（open 失敗を含む）を `OciOpKind::VerifyBlobDigest` として `recorder` へ記録する（REPAIR-4）。
pub fn verify_blob_digest_with(
    recorder: &dyn OciOpRecorder,
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    record_oci_op(recorder, OciOpKind::VerifyBlobDigest, || {
        verify_blob_digest_inner(path, expected, max_bytes)
    })
}

/// `path` の blob の sha256 を計算し `expected` と比較する（OCI-1）。
///
/// `max_bytes` は読み取り上限で、呼び出し側は `descriptor.size` または `RegistryClientConfig::max_blob_bytes`
/// を渡す。超過は `ResourceExhausted`、不一致は `DataLoss`、通常ファイル以外は `InvalidArgument`。
fn verify_blob_digest_inner(
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    let file = open_blob(path).map_err(map_io_error)?;
    // 同一ハンドルで種別を確認する（FIFO 等で読みがブロックするのを避ける）。
    let meta = file.metadata().map_err(map_io_error)?;
    if !meta.is_file() {
        return Err(OciError::new(
            OciErrorCode::InvalidArgument,
            "blob path is not a regular file",
        ));
    }
    let (hex, size) = sha256_hex_of_reader(file, max_bytes)?;
    let actual = format!("sha256:{hex}");
    if actual != expected.as_str() {
        return Err(OciError::new(
            OciErrorCode::DataLoss,
            "blob digest does not match the descriptor",
        ));
    }
    Ok(VerifiedBlob {
        digest: Digest::parse(&actual)?,
        size,
    })
}

/// `fetch_blob` の戻り値を、要求した digest に対して検証する薄いラッパー。
pub fn verify_fetched_blob(blob: &FetchedBlob, max_bytes: u64) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest(&blob.path, &blob.digest, max_bytes)
}

/// 計装つきの `verify_fetched_blob`。
pub fn verify_fetched_blob_with(
    recorder: &dyn OciOpRecorder,
    blob: &FetchedBlob,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest_with(recorder, &blob.path, &blob.digest, max_bytes)
}

/// Reader を EOF まで読み、小文字 hex の sha256 と読み取りバイト数を返す。
fn sha256_hex_of_reader<R: Read>(mut r: R, max_bytes: u64) -> Result<(String, u64), OciError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_LEN];
    let mut total: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io_error(e)),
        };
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "blob exceeds the size limit while hashing",
            ));
        }
        if let Some(chunk) = buf.get(..n) {
            hasher.update(chunk);
        }
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        // String への write は失敗しない。
        let _ = write!(hex, "{b:02x}");
    }
    Ok((hex, total))
}

/// I/O エラーを構造化エラーへ写す（パス・OS メッセージは載せない）。
fn map_io_error(e: std::io::Error) -> OciError {
    match e.kind() {
        ErrorKind::NotFound => OciError::new(OciErrorCode::NotFound, "blob file not found"),
        ErrorKind::PermissionDenied => {
            OciError::new(OciErrorCode::PermissionDenied, "blob file is not readable")
        }
        _ => OciError::new(OciErrorCode::Internal, "failed to read blob file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    const EMPTY: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const MSG: &str = "blob digest does not match the descriptor";

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-oci-layer-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn digest_of(data: &[u8]) -> Digest {
        let (hex, _) = sha256_hex_of_reader(data, u64::MAX).unwrap();
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    /// OCI-1: 既知ベクタで一致する。
    #[test]
    fn oci1_known_vectors_match() {
        let d = tmp_dir("known");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let v = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 10).unwrap();
        assert_eq!(v.digest.as_str(), ABC);
        assert_eq!(v.size, 3);
        std::fs::write(&p, b"").unwrap();
        let v = verify_blob_digest(&p, &Digest::parse(EMPTY).unwrap(), 10).unwrap();
        assert_eq!(v.size, 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1: 改ざん（書き換え・追記・切り詰め）は DataLoss。
    #[test]
    fn oci1_tampered_blob_is_rejected() {
        let d = tmp_dir("tamper");
        let p = d.join("b");
        let original = b"hello blob".to_vec();
        let expected = digest_of(&original);
        let mut flipped = original.clone();
        flipped[0] ^= 1;
        let mut appended = original.clone();
        appended.push(0);
        let truncated = original[..original.len() - 1].to_vec();
        for data in [flipped, appended, truncated] {
            std::fs::write(&p, &data).unwrap();
            let e = verify_blob_digest(&p, &expected, 1024).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::DataLoss);
            assert_eq!(e.code().as_str(), "DATA_LOSS");
            assert_eq!(e.message(), MSG);
        }
        std::fs::write(&p, &original).unwrap();
        assert!(verify_blob_digest(&p, &expected, 1024).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1: チャンク境界をまたぐ入力でも一貫する。
    #[test]
    fn oci1_multi_chunk_inputs() {
        let d = tmp_dir("chunks");
        let p = d.join("b");
        for len in [HASH_BUF_LEN, HASH_BUF_LEN + 1, HASH_BUF_LEN * 2] {
            let data = vec![0xa5u8; len];
            std::fs::write(&p, &data).unwrap();
            let v = verify_blob_digest(&p, &digest_of(&data), u64::MAX).unwrap();
            assert_eq!(v.size, len as u64);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oci1_size_limit_exceeded() {
        let d = tmp_dir("limit");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let e = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 2).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 3).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oci1_missing_and_directory_paths() {
        let d = tmp_dir("paths");
        let e = verify_blob_digest(&d.join("none"), &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        // ディレクトリは OS により open 自体が失敗するか通常ファイルでないとして拒否される。
        let e = verify_blob_digest(&d, &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert!(matches!(
            e.code(),
            OciErrorCode::InvalidArgument | OciErrorCode::PermissionDenied | OciErrorCode::Internal
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    struct Flaky {
        step: u8,
    }
    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.step += 1;
            match self.step {
                1 => Err(io::Error::from(ErrorKind::Interrupted)),
                2 => {
                    buf[..3].copy_from_slice(b"abc");
                    Ok(3)
                }
                _ => Ok(0),
            }
        }
    }

    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn oci1_interrupted_is_retried_and_other_errors_propagate() {
        let (hex, n) = sha256_hex_of_reader(Flaky { step: 0 }, 10).unwrap();
        assert_eq!(format!("sha256:{hex}"), ABC);
        assert_eq!(n, 3);
        let e = sha256_hex_of_reader(Broken, 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Internal);
    }

    #[test]
    fn oci1_verify_fetched_blob() {
        let d = tmp_dir("fetched");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let mut blob = FetchedBlob {
            path: p.clone(),
            size: 3,
            digest: Digest::parse(ABC).unwrap(),
        };
        assert_eq!(verify_fetched_blob(&blob, 10).unwrap().size, 3);
        blob.digest = Digest::parse(EMPTY).unwrap();
        let e = verify_fetched_blob(&blob, 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// REPAIR-5: 書き手のいない FIFO でも停止せず InvalidArgument で拒否する。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn oci1_fifo_does_not_hang() {
        let d = tmp_dir("fifo");
        let p = d.join("f");
        let st = std::process::Command::new("mkfifo").arg(&p).status();
        assert!(matches!(st, Ok(s) if s.success()), "mkfifo is required");
        let (tx, rx) = std::sync::mpsc::channel();
        let pc = p.clone();
        std::thread::spawn(move || {
            let r = verify_blob_digest(&pc, &Digest::parse(ABC).unwrap(), 10);
            let _ = tx.send(r);
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("verify must not block on a FIFO");
        assert_eq!(r.unwrap_err().code(), OciErrorCode::InvalidArgument);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[derive(Debug, Default)]
    struct Collect(std::sync::Mutex<Vec<crate::instrument::OciOpSample>>);
    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &crate::instrument::OciOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    /// REPAIR-4: 成功・DataLoss・open 失敗がそれぞれ 1 件記録される。
    #[test]
    fn oci1_verify_is_recorded() {
        use crate::instrument::OciOpOutcome;
        let d = tmp_dir("rec");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let c = Collect::default();
        verify_blob_digest_with(&c, &p, &Digest::parse(ABC).unwrap(), 10).unwrap();
        verify_blob_digest_with(&c, &p, &Digest::parse(EMPTY).unwrap(), 10).unwrap_err();
        verify_blob_digest_with(&c, &d.join("none"), &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        let v = c.0.lock().unwrap();
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|s| s.kind() == OciOpKind::VerifyBlobDigest));
        assert_eq!(v[0].outcome(), OciOpOutcome::Success);
        assert_eq!(v[0].error_code(), None);
        assert_eq!(v[1].error_code(), Some(OciErrorCode::DataLoss));
        assert_eq!(v[2].error_code(), Some(OciErrorCode::NotFound));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
